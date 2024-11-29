package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/rpc"
	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/utils"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	"go.sia.tech/renterd/api"
	"golang.org/x/crypto/blake2b"
)

var (
	errNoDirectory = errors.New("not a directory")
	errNoFiles     = errors.New("no files found")
)

type upload struct {
	uploadID  string
	partCount int
	parts     []api.MultipartCompletedPart
	totalSize uint64
	mu        sync.Mutex
}

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
	allocated     uint64
	ctx           context.Context
	cancel        context.CancelFunc
	lastSearch    string
	searchResults []api.ObjectMetadata
	pendingUpload *upload

	lsaFrames  map[uint32]*rpc.Frame
	srvsrcData []byte
	mu         sync.Mutex
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
		rand.Read(buf)
	}

	var filepath, filename string
	var isDir bool
	access := tc.maximalAccess
	name := strings.ToLower(info.Name)
	switch name {
	case "lsarpc", "srvsvc", "mdssvc":
		filename = name
		access = cr.DesiredAccess()
	default:
		filepath, filename, isDir = utils.ExtractFilename(info.Name)
	}

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
		grantedAccess:     access,
		currentEaIndex:    1,
		currentQuotaIndex: 1,
		fileName:          filename,
		pathName:          filepath,
		createOptions:     cr.CreateOptions(),
		fileAttributes:    smb2.FILE_ATTRIBUTE_NORMAL,
		lastModified:      time.Time(info.ModTime),
		size:              uint64(info.Size),
		allocated:         uint64(info.Size),
		ctx:               ctx,
		cancel:            cancel,
		lsaFrames:         make(map[uint32]*rpc.Frame),
	}

	if isDir {
		op.fileAttributes |= smb2.FILE_ATTRIBUTE_DIRECTORY
		op.fileAttributes = op.fileAttributes &^ smb2.FILE_ATTRIBUTE_NORMAL
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

func (s *server) restoreOpen(op *open) {
	op.session.mu.Lock()
	op.session.openTable[op.fileID] = op
	op.session.mu.Unlock()

	op.connection.server.mu.Lock()
	op.connection.server.globalOpenTable[op.durableFileID] = op
	op.connection.server.mu.Unlock()

	op.treeConnect.mu.Lock()
	op.treeConnect.openCount++
	op.treeConnect.mu.Unlock()
}

func (s *server) closeOpen(op *open, persist bool) {
	if !persist {
		op.cancel()
	}

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

func (op *open) queryDirectory(pattern string) error {
	if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errNoDirectory
	}

	share := op.treeConnect.share
	resp, err := share.client.GetObject(op.ctx, share.bucket, op.pathName+"/")
	if err != nil {
		return err
	}

	var results []api.ObjectMetadata
	for _, entry := range resp.Entries {
		_, name, _ := utils.ExtractFilename(entry.Name)
		match, _ := filepath.Match(pattern, name)
		if match {
			results = append(results, entry)
		}
	}

	op.lastSearch = pattern
	op.searchResults = results
	if len(results) == 0 {
		return errNoFiles
	}

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
	var lc uint32
	var pd bool
	if strings.ToLower(op.fileName) == "srvsvc" {
		alloc = 4096
		lc = 1
		pd = true
	} else if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		size = op.size
		alloc = op.allocated
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
			NumberOfLinks:  lc,
			DeletePending:  pd,
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

func (op *open) fileStandardInformation() []byte {
	var size, alloc uint64
	var lc uint32
	var pd bool
	if strings.ToLower(op.fileName) == "srvsvc" {
		alloc = 4096
		lc = 1
		pd = true
	} else if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		size = op.size
		alloc = op.allocated
	}
	fsi := smb2.FileStandardInfo{
		AllocationSize: alloc,
		EndOfFile:      size,
		NumberOfLinks:  lc,
		DeletePending:  pd,
		Directory:      op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY > 0,
	}
	return fsi.Encode()
}

func (op *open) fileNetworkOpenInformation() []byte {
	var size, alloc uint64
	if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		size = op.size
		alloc = op.allocated
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

func (op *open) newLSAFrame(ctx ntlm.SecurityContext) *rpc.Frame {
	op.mu.Lock()
	defer op.mu.Unlock()

	id := make([]byte, 16)
	rand.Read(id)
	guid, _ := dtyp.GUIDFromBytes(id)
	frame := &rpc.Frame{
		Handle: lsarpc.Handle{
			Attributes: 1,
			UUID:       guid,
		},
		SecurityContext: ctx,
	}

	op.lsaFrames[frame.Handle.UUID.Data1] = frame
	return frame
}

func (op *open) checkForChanges(req smb2.ChangeNotifyRequest, stopChan chan struct{}) {
	resp, err := op.treeConnect.share.client.GetObject(op.ctx, op.treeConnect.share.bucket, op.pathName)
	if err != nil {
		return
	}

	snapshot := makeSnapshot(resp.Entries)
	for {
		select {
		case <-stopChan:
			return
		case <-time.After(15 * time.Second):
		}

		resp, err := op.treeConnect.share.client.GetObject(op.ctx, op.treeConnect.share.bucket, op.pathName)
		if err != nil {
			continue
		}

		newSnapshot := makeSnapshot(resp.Entries)
		if !bytes.Equal(newSnapshot, snapshot) {
			resp := &smb2.ChangeNotifyResponse{}
			resp.FromRequest(req)
			resp.Header().SetStatus(smb2.STATUS_NOTIFY_ENUM_DIR)
			op.connection.server.writeResponse(op.connection, op.session, resp)
			op.connection.mu.Lock()
			delete(op.connection.stopChans, req.CancelRequestID())
			op.connection.mu.Unlock()
			return
		}
	}
}

func makeSnapshot(entries []api.ObjectMetadata) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		h.Write([]byte(entry.ETag))
		h.Write([]byte(entry.ModTime.String()))
		h.Write([]byte(entry.Name))
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(entry.Size)))
	}

	return h.Sum(nil)
}
