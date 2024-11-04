package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
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

	client         *client.Client
	bucket         string
	createdAt      time.Time
	volumeID       uint64
	sectorsPerUnit int
	mu             sync.Mutex
}

func (s *server) registerShare(name, serverName, apiPassword, bucketName string, connectSecurity map[string]struct{}, fileSecurity map[string]uint32, remark string) error {
	sh := &share{
		name:            name,
		serverName:      serverName,
		connectSecurity: connectSecurity,
		fileSecurity:    fileSecurity,
		shareType:       smb2.SHARE_TYPE_DISK,
		maxUses:         maxShareUses,
		remark:          remark,
	}

	sh.client = client.New(serverName, apiPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bucket, err := sh.client.GetBucket(ctx, bucketName)
	if err != nil {
		return errShareUnavailable
	}

	vid := make([]byte, 8)
	rand.Read(vid[:])

	spu, err := sh.client.SectorPerSlab(ctx)
	if err != nil || spu == 0 {
		return errShareUnavailable
	}

	sh.bucket = bucket.Name
	sh.createdAt = time.Time(bucket.CreatedAt)
	sh.volumeID = binary.LittleEndian.Uint64(vid)
	sh.sectorsPerUnit = spu
	s.mu.Lock()
	s.shareList[name] = sh
	s.mu.Unlock()

	return nil
}

func (sh *share) serialNo() uint32 {
	return uint32(sh.volumeID)
}
