package main

import (
	"errors"
	"time"

	"github.com/mike76-dev/siasmb/client"
	"github.com/mike76-dev/siasmb/smb2"
)

const (
	maxShareUses = 256
)

var (
	errShareUnavailable = errors.New("share currently unavailable")
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

	client    *client.Client
	bucket    string
	createdAt time.Time
}

func (s *server) registerShare(name, serverName, apiPassword, bucketName string, connectSecurity map[string]struct{}, fileSecurity map[string]uint32, remark string) error {
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

	sh.client = client.New(serverName, apiPassword)
	bucket, err := sh.client.GetBucket(bucketName)
	if err != nil {
		return errShareUnavailable
	}

	sh.bucket = bucket.Name
	sh.createdAt, _ = time.Parse(time.RFC3339, bucket.CreatedAt)
	s.mu.Lock()
	s.shareList[name] = sh
	s.mu.Unlock()

	return nil
}
