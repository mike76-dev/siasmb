package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

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
	sessionID       uint64
	state           int
	securityContext []byte
	isAnonymous     bool
	isGuest         bool
	sessionKey      []byte
	signingRequired bool
	// openTable
	// treeConnectTable
	expirationTime time.Time
	connection     *connection
	creationTime   time.Time
	idleTime       time.Time
	userName       string
	// channelList: 3.x
	// encryptData: 3.x
	// encryptionKey: 3.x
	// decryptionKey: 3.x
	// signingKey: 3.x
	// applicationKey: 3.x
	// supportsNotification: 3.x
	// preauthIntegrityHashValue: 3.1.1
	// fullSessionKey: 3.1.1
}

func (s *server) registerSession(connection *connection, req smb2.SessionSetupRequest) (*session, error) {
	var ss *session
	if req.Header.SessionID == 0 {
		sid := make([]byte, 8)
		rand.Read(sid)
		ss = &session{
			sessionID:    binary.LittleEndian.Uint64(sid),
			connection:   connection,
			state:        sessionInProgress,
			creationTime: time.Now(),
			idleTime:     time.Now(),
		}
		connection.mu.Lock()
		connection.sessionTable[ss.sessionID] = ss
		connection.mu.Unlock()
		s.mu.Lock()
		s.globalSessionTable[ss.sessionID] = ss
		s.stats.sOpens++
		s.mu.Unlock()
	} else {
		var found bool
		connection.mu.Lock()
		ss, found = connection.sessionTable[req.Header.SessionID]
		connection.mu.Unlock()
		if !found {
			return nil, errSessionNotFound
		}
		if ss.state == sessionExpired {
			ss.state = sessionInProgress
			ss.securityContext = nil
		}
	}
	return ss, nil
}

func (s *server) deregisterSession(connection *connection, req smb2.LogoffRequest) error {
	_, found := connection.sessionTable[req.Header.SessionID]
	if !found {
		return errSessionNotFound
	}

	connection.mu.Lock()
	delete(connection.sessionTable, req.Header.SessionID)
	connection.mu.Unlock()

	s.mu.Lock()
	delete(s.globalSessionTable, req.Header.SessionID)
	s.stats.sOpens--
	s.mu.Unlock()

	return nil
}
