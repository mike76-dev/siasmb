package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/utils"
	"go.sia.tech/renterd/api"
)

type open struct {
	fileID                      uint64
	durableFileID               uint64
	session                     *session
	treeConnect                 *treeConnect
	connection                  *connection
	grantedAccess               uint32
	oplockLevel                 uint8
	oplockState                 int
	oplockTimeout               time.Time
	isDurable                   bool
	durableOpenTimeout          time.Time
	durableOpenScavengerTimeout time.Time
	durableOwner                string
	currentEaIndex              uint32
	currentQuotaIndex           uint32
	lockCount                   int
	pathName                    string
	resumeKey                   []byte
	fileName                    string
	createOptions               uint32
	fileAttributes              uint32

	lastModified time.Time
	size         uint64
}

func (s *server) findOpen(path string, treeID uint32) (*open, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, op := range s.globalOpenTable {
		if op.pathName == path && op.treeConnect.treeID == treeID {
			return op, true
		}
	}

	return nil, false
}

func grantAccess(cr smb2.CreateRequest, tc *treeConnect, ss *session) bool {
	if tc.share.connectSecurity == nil || tc.share.fileSecurity == nil {
		return true
	}

	_, ok := tc.share.connectSecurity[ss.userName]
	if !ok {
		return false
	}

	fs := tc.share.fileSecurity[ss.userName]
	write := fs&(smb2.FILE_WRITE_DATA|smb2.FILE_APPEND_DATA|smb2.FILE_WRITE_EA|smb2.FILE_WRITE_ATTRIBUTES) > 0
	del := fs&(smb2.DELETE|smb2.FILE_DELETE_CHILD) > 0

	cd := cr.CreateDisposition()
	co := cr.CreateOptions()
	da := cr.DesiredAccess()

	if fs&da == 0 {
		return false
	}

	if !write && ((cd&(smb2.FILE_SUPERSEDE|smb2.FILE_CREATE|smb2.FILE_OPEN_IF|smb2.FILE_OVERWRITE|smb2.FILE_OVERWRITE_IF) > 0) || (co&smb2.FILE_WRITE_THROUGH > 0)) {
		return false
	}

	if !del && (co&smb2.FILE_DELETE_ON_CLOSE > 0) {
		return false
	}

	return true
}

func (ss *session) registerOpen(cr smb2.CreateRequest, tc *treeConnect, info api.ObjectMetadata) *open {
	fid := make([]byte, 8)
	rand.Read(fid)

	var dfid []byte
	if info.ETag == "" {
		dfid = make([]byte, 8)
		binary.LittleEndian.PutUint64(dfid, tc.share.volumeID)
	} else {
		var err error
		dfid, err = hex.DecodeString(info.ETag)
		if err != nil || len(dfid) < 8 {
			return nil
		}
	}

	filepath, filename, isDir := utils.ExtractFilename(info.Name)

	op := &open{
		fileID:            binary.LittleEndian.Uint64(fid[:8]),
		durableFileID:     binary.LittleEndian.Uint64(dfid[:8]),
		session:           ss,
		connection:        ss.connection,
		treeConnect:       tc,
		oplockLevel:       smb2.OPLOCK_LEVEL_NONE,
		oplockState:       smb2.OplockNone,
		durableOwner:      ss.userName,
		grantedAccess:     tc.maximalAccess,
		currentEaIndex:    1,
		currentQuotaIndex: 1,
		fileName:          filename,
		pathName:          filepath,
		createOptions:     cr.CreateOptions(),
		fileAttributes:    cr.FileAttributes(),
		lastModified:      time.Time(info.ModTime),
		size:              uint64(info.Size),
	}

	if isDir {
		op.fileAttributes |= smb2.FILE_ATTRIBUTE_DIRECTORY
	}

	ss.mu.Lock()
	ss.openTable[op.fileID] = op
	ss.mu.Unlock()

	ss.connection.server.mu.Lock()
	ss.connection.server.globalOpenTable[op.durableFileID] = op
	ss.connection.server.mu.Unlock()

	tc.mu.Lock()
	tc.openCount++
	tc.mu.Unlock()

	return op
}
