package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

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
	h := hmac.New(sha256.New, ss.sessionKey)
	for {
		next := binary.LittleEndian.Uint32(buf[off+20 : off+24])
		flags := binary.LittleEndian.Uint32(buf[off+16 : off+20])
		binary.LittleEndian.PutUint32(buf[off+16:off+20], flags|smb2.FLAGS_SIGNED)
		copy(buf[off+48:off+64], zero[:])
		h.Reset()
		if next == 0 { // Last response in the chain
			h.Write(buf[off:])
		} else {
			h.Write(buf[off : off+next])
		}
		copy(buf[off+48:off+64], h.Sum(nil))
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
	h := hmac.New(sha256.New, ss.sessionKey)
	h.Reset()
	h.Write(req.Header())
	sum := h.Sum(nil)
	return bytes.Equal(signature, sum[:16])
}
