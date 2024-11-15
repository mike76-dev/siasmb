package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/utils"
	"go.sia.tech/renterd/api"
)

var (
	errNoDirectory = errors.New("not a directory")
)

type open struct {
	handle                      uint64
	fileID                      uint64
	durableFileID               uint64
	session                     *session
	treeConnect                 *treeConnect
	connection                  *connection
	grantedAccess               uint32
	oplockLevel                 uint8
	oplockState                 int
	oplockTimeout               time.Duration
	isDurable                   bool
	durableOpenTimeout          time.Duration
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

	lastModified  time.Time
	size          uint64
	ctx           context.Context
	cancel        context.CancelFunc
	lastSearch    string
	searchResults []api.ObjectMetadata
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

func (ss *session) registerOpen(cr smb2.CreateRequest, tc *treeConnect, info api.ObjectMetadata, ctx context.Context, cancel context.CancelFunc) *open {
	id := make([]byte, 16)
	rand.Read(id)

	var buf []byte
	if info.ETag != "" {
		var err error
		buf, err = hex.DecodeString(info.ETag)
		if err != nil || len(buf) < 8 {
			return nil
		}
	} else {
		buf = make([]byte, 8)
		copy(buf, tc.share.name)
	}

	filepath, filename, isDir := utils.ExtractFilename(info.Name)
	op := &open{
		handle:            binary.LittleEndian.Uint64(buf[:8]),
		fileID:            binary.LittleEndian.Uint64(id[:8]),
		durableFileID:     binary.LittleEndian.Uint64(id[8:]),
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
		ctx:               ctx,
		cancel:            cancel,
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

func (s *server) closeOpen(op *open) {
	op.cancel()

	op.treeConnect.mu.Lock()
	op.treeConnect.openCount--
	op.treeConnect.mu.Unlock()

	op.session.mu.Lock()
	delete(op.session.openTable, op.fileID)
	op.session.mu.Unlock()

	s.mu.Lock()
	delete(s.globalOpenTable, op.durableFileID)
	s.mu.Unlock()
}

func (op *open) queryDirectory(path string) error {
	if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errNoDirectory
	}

	p := op.pathName
	if path != "*" {
		p += path + "/"
	} else {
		p += "/"
	}

	share := op.treeConnect.share
	resp, err := share.client.GetObject(op.ctx, share.bucket, p)
	if err != nil {
		return err
	}

	op.lastSearch = path
	op.searchResults = resp.Entries
	return nil
}

func (op *open) id() []byte {
	i := make([]byte, 16)
	binary.LittleEndian.PutUint64(i[:8], op.fileID)
	binary.LittleEndian.PutUint64(i[8:], op.durableFileID)
	return i
}

func (op *open) fileAllInformation() []byte {
	var size, alloc uint64
	if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		size = op.size
		alloc = (op.size + (smb2.ClusterSize - 1)) &^ (smb2.ClusterSize - 1)
	}
	fai := smb2.FileAllInfo{
		BasicInfo: smb2.FileBasicInfo{
			CreationTime:   op.lastModified,
			LastAccessTime: op.lastModified,
			LastWriteTime:  op.lastModified,
			ChangeTime:     op.lastModified,
			FileAttributes: op.fileAttributes,
		},
		StandardInfo: smb2.FileStandardInfo{
			AllocationSize: alloc,
			EndOfFile:      size,
			Directory:      op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY > 0,
		},
		InternalInfo: smb2.FileInternalInfo{
			IndexNumber: op.handle,
		},
		AccessInfo: smb2.FileAccessInfo{
			AccessFlags: op.grantedAccess,
		},
		ModeInfo: smb2.FileModeInfo{
			Mode: op.createOptions,
		},
		NameInfo: smb2.FileNameInfo{
			FileName: op.fileName,
		},
	}
	return fai.Encode()
}

func (op *open) fileNetworkOpenInformation() []byte {
	var size, alloc uint64
	if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		size = op.size
		alloc = (op.size + (smb2.ClusterSize - 1)) &^ (smb2.ClusterSize - 1)
	}
	fnoi := smb2.FileNetworkOpenInfo{
		CreationTime:   op.lastModified,
		LastAccessTime: op.lastModified,
		LastWriteTime:  op.lastModified,
		ChangeTime:     op.lastModified,
		AllocationSize: alloc,
		EndOfFile:      size,
		FileAttributes: op.fileAttributes,
	}
	return fnoi.Encode()
}
