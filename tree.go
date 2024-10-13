package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

var (
	errNoShare       = errors.New("no share name provided")
	errNoTreeConnect = errors.New("tree already disconnected")
)

type treeConnect struct {
	treeID        uint32
	session       *session
	share         string //TODO
	openCount     uint64
	creationTime  time.Time
	maximalAccess uint32
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

	return path[pos+1:]
}

func (c *connection) newTreeConnect(ss *session, path string, access uint32) (*treeConnect, error) {
	share := extractShareName(path)
	if share == "" {
		return nil, errNoShare
	}

	var id [4]byte
	rand.Read(id[:])

	tc := &treeConnect{
		treeID:        binary.LittleEndian.Uint32(id[:]),
		session:       ss,
		share:         share,
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

	if _, ok := ss.treeConnectTable[tid]; !ok {
		return errNoTreeConnect
	}

	delete(ss.treeConnectTable, tid)

	return nil
}
