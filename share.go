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
	"go.sia.tech/indexd/sdk"
)

const (
	maxShareUses = 256 // Not sure if this is a sensible number, real-life testing will show
)

var (
	errShareUnavailable = errors.New("share currently unavailable")
	errShareExists      = errors.New("share with the same name already exists")
	errShareNotFound    = errors.New("share not found")
	errShareInUse       = errors.New("share currently in use by one or more clients")
)

// share represents a Share object.
type share struct {
	name            string
	serverName      string
	connectSecurity map[string]struct{}
	fileSecurity    map[string]uint32
	shareType       uint8
	remark          string
	maxUses         int
	currentUses     int
	encryptData     bool
	compressData    bool

	// Auxiliary fields.
	client     client.Client
	dataShards uint8
	backend    string
	bucket     string
	appKey     types.PrivateKey
	createdAt  time.Time
	volumeID   uint64
	mu         sync.Mutex
}

// registerShare adds a new share to the SMB server.
func (s *server) registerShare(ss stores.Share) (*share, error) {
	s.mu.Lock()
	_, found := s.shareList[ss.Name]
	s.mu.Unlock()
	if found {
		return nil, errShareExists
	}

	sh := &share{
		name:            ss.Name,
		backend:         ss.Type,
		serverName:      ss.ServerName,
		shareType:       smb2.SHARE_TYPE_DISK,
		maxUses:         maxShareUses,
		bucket:          ss.Bucket,
		remark:          ss.Remark,
		appKey:          ss.AppKey,
		connectSecurity: make(map[string]struct{}),
		fileSecurity:    make(map[string]uint32),
		encryptData:     s.encryptData,
		compressData:    s.compressionSupported,
		dataShards:      s.cfg.DataShards,
	}

	switch sh.backend {
	case "indexd":
		builder := sdk.NewBuilder(ss.ServerName, sdk.AppMetadata{
			ID:          types.HashBytes(append([]byte(s.cfg.Name), []byte(s.cfg.Description)...)),
			Name:        s.cfg.Name,
			Description: s.cfg.Description,
			LogoURL:     s.cfg.LogoURL,
			ServiceURL:  s.cfg.ServiceURL,
		})
		sdkClient, err := builder.SDK(ss.AppKey)
		if err != nil {
			return nil, err
		}
		sh.client = client.NewIndexdClient(s.store, sdkClient, ss.Name, s.cfg.DataShards, s.cfg.ParityShards)
	case "renterd":
		sh.client = client.NewRenterdClient(ss.ServerName, ss.Password, ss.Bucket)
	default:
		return nil, errors.New("unsupported share type")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get the share information and test the share at the same time.
	info, err := sh.client.Info(ctx)
	if err != nil {
		return nil, errShareUnavailable
	}

	ars, err := s.store.GetAccounts(ss)
	if err != nil {
		return nil, err
	}

	accs := make(map[int]stores.Account)
	for _, ar := range ars {
		if _, exists := accs[ar.AccountID]; !exists {
			acc, err := s.store.GetAccountByID(ar.AccountID)
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
	sh.bucket = info.Bucket
	sh.createdAt = time.Time(info.CreatedAt)
	sh.volumeID = binary.LittleEndian.Uint64(vid)
	s.mu.Lock()
	s.shareList[sh.name] = sh
	s.mu.Unlock()

	return sh, nil
}

// serialNo is a helper function that derives the share's "serial number" from its "volume ID".
func (sh *share) serialNo() uint32 {
	return uint32(sh.volumeID)
}

// RemoveShare removes a share from the SMB server.
func (s *server) RemoveShare(ss stores.Share) error {
	s.mu.Lock()
	sh, found := s.shareList[ss.Name]
	s.mu.Unlock()
	if !found {
		return errShareNotFound
	}

	sh.mu.Lock()
	if sh.currentUses > 0 {
		sh.mu.Unlock()
		return errShareInUse
	}
	sh.mu.Unlock()

	s.mu.Lock()
	delete(s.shareList, ss.Name)
	s.mu.Unlock()

	return nil
}
