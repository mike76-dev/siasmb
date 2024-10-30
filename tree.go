package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/smb2"
)

var (
	errNoShare       = errors.New("no share name provided")
	errNoTreeConnect = errors.New("tree already disconnected")
	errAccessDenied  = errors.New("access denied")
)

type treeConnect struct {
	treeID        uint32
	session       *session
	share         *share
	openCount     uint64
	creationTime  time.Time
	maximalAccess uint32
	mu            sync.Mutex
}

func extractShareName(path string) string {
	var ok bool
	path, ok = strings.CutPrefix(path, "\\\\")
	if !ok {
		return ""
	}

	pos := strings.Index(path, "\\")
	if pos == -1 {
		return ""
	}

	if pos == len(path)-1 {
		return ""
	}

	return strings.ToLower(path[pos+1:])
}

func (c *connection) newTreeConnect(ss *session, path string) (*treeConnect, error) {
	name := extractShareName(path)
	if name == "" {
		return nil, errNoShare
	}

	var sh *share
	var access uint32
	if name == "ipc$" {
		sh = &share{
			name:            name,
			shareType:       smb2.SHARE_TYPE_PIPE,
			connectSecurity: map[string]struct{}{},
			fileSecurity:    make(map[string]uint32),
		}
		sh.connectSecurity[ss.userName] = struct{}{}
		access = smb2.FILE_READ_DATA |
			smb2.FILE_READ_EA |
			smb2.FILE_EXECUTE |
			smb2.FILE_READ_ATTRIBUTES |
			smb2.DELETE |
			smb2.READ_CONTROL |
			smb2.WRITE_DAC |
			smb2.WRITE_OWNER |
			smb2.SYNCHRONIZE
		sh.fileSecurity[ss.userName] = access
	} else {
		var exists bool
		c.server.mu.Lock()
		sh, exists = c.server.shareList[name]
		c.server.mu.Unlock()
		if !exists {
			return nil, errNoShare
		}
		access, exists = sh.fileSecurity[ss.userName]
		if !exists {
			return nil, errAccessDenied
		}
		sh.mu.Lock()
		sh.currentUses++
		sh.mu.Unlock()
	}

	var id [4]byte
	rand.Read(id[:])

	tc := &treeConnect{
		treeID:        binary.LittleEndian.Uint32(id[:]),
		session:       ss,
		share:         sh,
		creationTime:  time.Now(),
		maximalAccess: access,
	}

	ss.mu.Lock()
	ss.treeConnectTable[tc.treeID] = tc
	ss.mu.Unlock()

	return tc, nil
}

func (ss *session) closeTreeConnect(tid uint32) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	tc, ok := ss.treeConnectTable[tid]
	if !ok {
		return errNoTreeConnect
	}

	for fid, op := range ss.openTable {
		if op.treeConnect == tc {
			delete(ss.openTable, fid)
			ss.connection.server.mu.Lock()
			delete(ss.connection.server.globalOpenTable, fid)
			ss.connection.server.mu.Unlock()
		}
	}

	tc.share.mu.Lock()
	tc.share.currentUses--
	tc.share.mu.Unlock()

	delete(ss.treeConnectTable, tid)

	return nil
}
