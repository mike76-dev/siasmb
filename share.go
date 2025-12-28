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
	"github.com/mike76-dev/siasmb/stores"
	"go.sia.tech/core/types"
)

const (
	maxShareUses = 256 // Not sure if this is a sensible number, real-life testing will show
)

var (
	errShareUnavailable = errors.New("share currently unavailable")
)

// share represents a Share object.
type share struct {
	id                                types.Hash256
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
	encryptData                       bool

	// Auxiliary fields.
	client    *client.Client
	bucket    string
	createdAt time.Time
	volumeID  uint64
	mu        sync.Mutex
}

// registerShare adds a new share to the SMB server.
func (s *server) registerShare(ss stores.Share, st Store) (*share, error) {
	if isIndexd {
		return nil, nil // indexd is not supported yet.
	}

	sh := &share{
		id:              ss.ID,
		name:            ss.Name,
		serverName:      ss.ServerName,
		shareType:       smb2.SHARE_TYPE_DISK,
		maxUses:         maxShareUses,
		bucket:          ss.Bucket,
		remark:          ss.Remark,
		connectSecurity: make(map[string]struct{}),
		fileSecurity:    make(map[string]uint32),
		encryptData:     s.encryptData,
	}

	sh.client = client.New(ss.ServerName, ss.Password)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get the bucket information and test the share at the same time.
	bucket, err := sh.client.GetBucket(ctx, ss.Bucket)
	if err != nil {
		return nil, errShareUnavailable
	}

	ars, err := st.GetAccounts(ss)
	if err != nil {
		return nil, err
	}

	accs := make(map[int]stores.Account)
	for _, ar := range ars {
		if _, exists := accs[ar.AccountID]; !exists {
			acc, err := st.GetAccountByID(ar.AccountID)
			if err != nil {
				return nil, err
			}
			accs[ar.AccountID] = acc
		}
	}

	sh.mu.Lock()
	for _, ar := range ars {
		acc := accs[ar.AccountID]
		sh.connectSecurity[acc.Workgroup+"/"+acc.Username] = struct{}{}
		sh.fileSecurity[acc.Workgroup+"/"+acc.Username] = stores.FlagsFromAccessRights(ar)
	}
	sh.mu.Unlock()

	vid := make([]byte, 8)
	rand.Read(vid[:])
	sh.bucket = bucket.Name
	sh.createdAt = time.Time(bucket.CreatedAt)
	sh.volumeID = binary.LittleEndian.Uint64(vid)
	s.mu.Lock()
	s.shareList[string(sh.id[:])+"/"+sh.name] = sh
	s.mu.Unlock()

	return sh, nil
}

// serialNo is a helper function that derives the share's "serial number" from its "volume ID".
func (sh *share) serialNo() uint32 {
	return uint32(sh.volumeID)
}
