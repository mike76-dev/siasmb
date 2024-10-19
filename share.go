package main

import "github.com/mike76-dev/siasmb/smb2"

const (
	maxShareUses = 256
)

type share struct {
	name                              string
	serverName                        string
	connectSecurity                   map[string]struct{}
	fileSecurity                      map[string]uint32
	cscFlags                          uint32
	isDfs                             bool
	doAccessBasedDirectoryEnumeration bool
	allowNamespaceCaching             bool
	forceSharedDelete                 bool
	restrictExclusiveOpens            bool
	shareType                         uint8
	remark                            string
	maxUses                           int
	currentUses                       int
	forceLevel2Oplock                 bool
	hashEnabled                       bool
	// snapshotList
}

func (s *server) registerShare(name, serverName string, connectSecurity map[string]struct{}, fileSecurity map[string]uint32, remark string) {
	sh := &share{
		name:            name,
		serverName:      serverName,
		connectSecurity: connectSecurity,
		fileSecurity:    fileSecurity,
		cscFlags:        smb2.SHAREFLAG_DFS,
		isDfs:           true,
		shareType:       smb2.SHARE_TYPE_DISK,
		maxUses:         maxShareUses,
		remark:          remark,
	}

	s.mu.Lock()
	s.shareList[name] = sh
	s.mu.Unlock()
}
