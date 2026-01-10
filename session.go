package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"log"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/internal/ccm"
	"github.com/mike76-dev/siasmb/internal/cmac"
	"github.com/mike76-dev/siasmb/kdf"
	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/smb2"
)

const (
	sessionInProgress int = iota
	sessionValid
	sessionExpired
)

var (
	errSessionNotFound = errors.New("session not found")
)

// session represents a Session object.
type session struct {
	sessionID        uint64
	state            int
	securityContext  ntlm.SecurityContext
	isAnonymous      bool
	isGuest          bool
	sessionKey       []byte
	signingRequired  bool
	openTable        map[uint64]*open
	treeConnectTable map[uint32]*treeConnect
	expirationTime   time.Time
	connection       *connection
	creationTime     time.Time
	idleTime         time.Time
	userName         string
	workgroup        string
	encryptData      bool
	encryptionKey    []byte
	decryptionKey    []byte
	applicationKey   []byte
	signer           hash.Hash
	verifier         hash.Hash
	encrypter        cipher.Block
	decrypter        cipher.Block

	mu sync.Mutex
}

// registerSession creates a new Session object and registers it with the SMB server.
func (s *server) registerSession(connection *connection, req smb2.SessionSetupRequest) (*session, bool, error) {
	var ss *session
	var found bool
	if req.Header().SessionID() == 0 { // A new session
		sid := make([]byte, 8)
		rand.Read(sid)
		ss = &session{
			sessionID:        binary.LittleEndian.Uint64(sid),
			connection:       connection,
			state:            sessionInProgress,
			creationTime:     time.Now(),
			idleTime:         time.Now(),
			openTable:        make(map[uint64]*open),
			treeConnectTable: make(map[uint32]*treeConnect),
		}
		connection.mu.Lock()
		connection.sessionTable[ss.sessionID] = ss
		connection.mu.Unlock()
		s.mu.Lock()
		s.globalSessionTable[ss.sessionID] = ss
		s.stats.sOpens++
		s.mu.Unlock()
	} else { // There is already a session with this ID, reactivate it
		connection.mu.Lock()
		ss, found = connection.sessionTable[req.Header().SessionID()]
		connection.mu.Unlock()
		if !found {
			return nil, false, errSessionNotFound
		}
		if ss.state == sessionExpired {
			ss.state = sessionInProgress
			ss.securityContext = ntlm.SecurityContext{}
		}
	}
	return ss, found, nil
}

// deregisterSession destroys the Session object and closes all associated tree connections.
func (s *server) deregisterSession(connection *connection, sid uint64) (*session, error) {
	ss, found := connection.sessionTable[sid]
	if !found {
		return nil, errSessionNotFound
	}

	ss.mu.Lock()
	for _, op := range ss.openTable {
		if op.isDurable {
			op.session = nil
			op.connection = nil
			op.treeConnect = nil
			op.durableOpenScavengerTimeout = time.Now().Add(op.durableOpenTimeout)
		} else {
			s.mu.Lock()
			delete(ss.connection.server.globalOpenTable, op.durableFileID)
			s.mu.Unlock()
		}
		op.cancel()
	}
	ss.mu.Unlock()

	for tid := range ss.treeConnectTable {
		ss.closeTreeConnect(tid)
	}

	connection.mu.Lock()
	delete(connection.sessionTable, sid)
	connection.mu.Unlock()

	s.mu.Lock()
	delete(s.globalSessionTable, sid)
	s.stats.sOpens--
	s.mu.Unlock()

	return ss, nil
}

// finalize finalizes the session after successfully authenticating the user.
func (ss *session) finalize(req smb2.SessionSetupRequest) {
	ss.securityContext = ss.connection.ntlmServer.Session().GetSecurityContext()
	ss.userName = ss.connection.ntlmServer.Session().User()
	ss.workgroup = ss.connection.ntlmServer.Session().Domain()
	if ss.userName == "" {
		ss.isAnonymous = true
	}
	if ss.userName == "guest" {
		ss.isGuest = true
	}
	ss.signingRequired = (req.SecurityMode()&smb2.NEGOTIATE_SIGNING_REQUIRED > 0) && !ss.isAnonymous && !ss.isGuest && ss.connection.shouldSign
	ss.sessionKey = ss.connection.ntlmServer.Session().SessionKey()
	ss.encryptData = ss.connection.server.encryptData

	if ss.connection.server.debug {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, ss.sessionID)
		log.Printf("Session ID: %x\n", buf)
		log.Printf("Session key: %x\n", ss.sessionKey)
	}

	switch ss.connection.negotiateDialect {
	case smb2.SMB_DIALECT_202, smb2.SMB_DIALECT_21:
		ss.signer = hmac.New(sha256.New, ss.sessionKey)
		ss.verifier = hmac.New(sha256.New, ss.sessionKey)
	case smb2.SMB_DIALECT_30, smb2.SMB_DIALECT_302:
		signingKey := kdf.Kdf(ss.sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			panic(err)
		}
		ss.signer = cmac.New(ciph)
		ss.verifier = cmac.New(ciph)

		ss.applicationKey = kdf.Kdf(ss.sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))
		ss.encryptionKey = kdf.Kdf(ss.sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))
		ss.decryptionKey = kdf.Kdf(ss.sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))

		ciph, err = aes.NewCipher(ss.encryptionKey)
		if err != nil {
			panic(err)
		}
		ss.encrypter = ciph

		ciph, err = aes.NewCipher(ss.decryptionKey)
		if err != nil {
			panic(err)
		}
		ss.decrypter = ciph
	}

	ss.connection.mu.Lock()
	defer ss.connection.mu.Unlock()

	if req.PreviousSessionID() != 0 { // This session replaces another one; delete the previous one
		pss, found := ss.connection.sessionTable[req.PreviousSessionID()]
		if found && ss.securityContext.UserRID == pss.securityContext.UserRID && ss.sessionID != req.PreviousSessionID() {
			delete(ss.connection.sessionTable, req.PreviousSessionID())
			ss.connection.server.mu.Lock()
			delete(ss.connection.server.globalSessionTable, req.PreviousSessionID())
			ss.connection.server.mu.Unlock()
		}
	}

	ss.state = sessionValid
	ss.expirationTime = time.Now().Add(100 * 365 * 24 * time.Hour) // Impossibly long
}

// sign uses the session key to sign each response in the message.
func (ss *session) sign(buf []byte) {
	var off uint32
	var zero [16]byte
	for {
		next := binary.LittleEndian.Uint32(buf[off+20 : off+24])
		flags := binary.LittleEndian.Uint32(buf[off+16 : off+20])
		binary.LittleEndian.PutUint32(buf[off+16:off+20], flags|smb2.FLAGS_SIGNED)
		copy(buf[off+48:off+64], zero[:])
		ss.signer.Reset()
		if next == 0 { // Last response in the chain
			ss.signer.Write(buf[off:])
		} else {
			ss.signer.Write(buf[off : off+next])
		}
		copy(buf[off+48:off+64], ss.signer.Sum(nil))
		off += next
		if next == 0 {
			break
		}
	}
}

// validateRequest returns true if the request is correctly signed by the client.
func (ss *session) validateRequest(req *smb2.Request) bool {
	if !req.Header().IsFlagSet(smb2.FLAGS_SIGNED) {
		return true
	}

	signature := req.Header().Signature()
	req.Header().WipeSignature()
	ss.verifier.Reset()
	ss.verifier.Write(req.Header())
	sum := ss.verifier.Sum(nil)
	return bytes.Equal(signature, sum[:16])
}

// encrypt uses the encryption key to encrypt the SMB message.
func (ss *session) encrypt(buf []byte) []byte {
	encrypter, err := ccm.NewCCMWithNonceAndTagSizes(ss.encrypter, 11, 16)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, encrypter.NonceSize())
	rand.Read(nonce)
	output := smb2.Header(make([]byte, smb2.SMB2TransformHeaderSize+len(buf)+16))
	output.SetProtocolID(smb2.PROTOCOL_SMB2_ENCRYPTED)
	output.SetNonce(nonce)
	output.SetOriginalMessageSize(uint32(len(buf)))
	output.SetEncryptionFlags(1)
	output.SetTransformSessionID(ss.sessionID)
	encrypter.Seal(output[:smb2.SMB2TransformHeaderSize], nonce, buf, output.AssociatedData())
	output.SetEncryptionSignature(output[len(output)-16:])
	output = output[:len(output)-16]
	return output
}

// decrypt uses the decryption key to decrypt the SMB message.
func (ss *session) decrypt(buf []byte) []byte {
	input := append(buf[smb2.SMB2TransformHeaderSize:], smb2.Header(buf).EncryptionSignature()...)
	decrypter, err := ccm.NewCCMWithNonceAndTagSizes(ss.decrypter, 11, 16)
	if err != nil {
		panic(err)
	}
	msg, err := decrypter.Open(input[:0], smb2.Header(buf).Nonce()[:decrypter.NonceSize()], input, smb2.Header(buf).AssociatedData())
	if err != nil {
		log.Printf("Decryption error at session %d: %v", ss.sessionID, err)
		return nil
	}
	return msg
}
