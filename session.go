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

	mu sync.Mutex
}

func (s *server) registerSession(connection *connection, req smb2.SessionSetupRequest) (*session, bool, error) {
	var ss *session
	var found bool
	if req.Header().SessionID() == 0 {
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
	} else {
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

func (s *server) deregisterSession(connection *connection, sid uint64) (*session, error) {
	ss, found := connection.sessionTable[sid]
	if !found {
		return nil, errSessionNotFound
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

func (ss *session) validate(req smb2.SessionSetupRequest) {
	ss.securityContext = ss.connection.ntlmServer.Session().GetSecurityContext()
	ss.userName = ss.connection.ntlmServer.Session().User()
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

	if req.PreviousSessionID() != 0 {
		pss, found := ss.connection.sessionTable[req.PreviousSessionID()]
		if found && ss.securityContext.UserSID == pss.securityContext.UserSID && ss.sessionID != req.PreviousSessionID() {
			delete(ss.connection.sessionTable, req.PreviousSessionID())
			ss.connection.server.mu.Lock()
			delete(ss.connection.server.globalSessionTable, req.PreviousSessionID())
			ss.connection.server.mu.Unlock()
		}
	}

	ss.state = sessionValid
	ss.expirationTime = time.Now().Add(100 * 365 * 24 * time.Hour)
}

func (ss *session) sign(buf []byte) {
	flags := binary.LittleEndian.Uint32(buf[16:20])
	binary.LittleEndian.PutUint32(buf[16:20], flags|smb2.FLAGS_SIGNED)
	var zero [16]byte
	copy(buf[48:64], zero[:])
	h := hmac.New(sha256.New, ss.sessionKey)
	h.Reset()
	h.Write(buf)
	copy(buf[48:64], h.Sum(nil))
}

func (ss *session) validateRequest(req *smb2.Request) bool {
	if !req.Header().IsFlagSet(smb2.FLAGS_SIGNED) {
		return true
	}

	signature := req.Header().Signature()
	req.Header().WipeSignature()
	ss.sign(req.Header())
	return bytes.Equal(signature, req.Header().Signature())
}
