package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
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
	"go.sia.tech/renterd/v2/api"
	"golang.org/x/crypto/blake2b"
)

var (
	errNoDirectory = errors.New("not a directory")
	errNoFiles     = errors.New("no files found")
)

// upload holds the information about an active multipart upload.
type upload struct {
	uploadID  string
	partCount int
	parts     []api.MultipartCompletedPart
	totalSize uint64
	mu        sync.Mutex
}

// open represents an Open object.
type open struct {
	// The handle is what uniquely identifies the file within a share.
	// It is deterministically derived from the path of the object.
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
	createGuid                  [16]byte

	// Since renterd has no idea about such attributes of the most operating systems as
	// CreationTime, LastWriteTime, LastAccessTime, and ChangeTime, we can only operate
	// with the lastModified property.
	lastModified time.Time

	// size is how much space the file occupies.
	// allocated in most cases means the same, except when a file is being uploaded.
	// In such case, it may hold the future size of the file (it depends on the client, though).
	size      uint64
	allocated uint64

	ctx    context.Context
	cancel context.CancelFunc

	// The parameters and the result of the most recent search done on a directory (if the current open
	// is a directory). It is needed, because it's common for the clients to send two consecutive
	// SMB2_QUERY_DIRECTORY requests; the second one should be responded with the NO_MORE_FILES status.
	lastSearch    string
	searchResults []api.ObjectMetadata

	// if pendingUpload is not nil, it points to an active multipart upload.
	pendingUpload *upload

	// SMB 2.0.2 dialect has a limitation of the chunk size of 64KiB. In order to mitigate this,
	// read buffering is implemented. The buffer consists of several caches, because the SMB2_READ
	// requests may come out of order.
	buffer       map[uint64][]byte
	cacheOrder   []uint64
	chunkSize    uint64
	maxCacheSize int

	// A collection of LSARPS frames (if the open is associated with the IPC$ share).
	lsaFrames map[uint32]*rpc.Frame

	// SRVSVC data written to or read from the SRVSVC named pipe
	// (if the open is associated with the IPC$ share).
	srvsvcData []byte

	mu sync.Mutex
}

// grantAccess returns true if the user's access rights are sufficient for performing the requested operation(s) on the file.
func grantAccess(cr smb2.CreateRequest, tc *treeConnect, ss *session) bool {
	if tc.share.connectSecurity == nil || tc.share.fileSecurity == nil {
		return true
	}

	_, ok := tc.share.connectSecurity[ss.workgroup+"/"+ss.userName]
	if !ok {
		return false
	}

	fs := tc.share.fileSecurity[ss.workgroup+"/"+ss.userName]
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

// registerOpen creates a new Open object and registers it with the server.
func (ss *session) registerOpen(cr smb2.CreateRequest, tc *treeConnect, info api.ObjectMetadata, ctx context.Context, cancel context.CancelFunc) *open {
	h, _ := blake2b.New256(nil)
	h.Write([]byte(info.Key))
	id := h.Sum(nil)

	var filepath, filename string
	var isDir bool
	access := tc.maximalAccess
	name := strings.ToLower(info.Key)
	switch name {
	case "lsarpc", "srvsvc", "mdssvc": // Standard named pipes on MacOS, Linux, and Windows
		filename = name
		filepath = name
		access = cr.DesiredAccess()
	default:
		filepath, filename, isDir = utils.ExtractFilename(info.Key)
	}

	fid := make([]byte, 16)
	rand.Read(fid)
	op := &open{
		handle:            binary.LittleEndian.Uint64(id[:8]),
		fileID:            binary.LittleEndian.Uint64(fid[:8]),
		durableFileID:     binary.LittleEndian.Uint64(fid[8:]),
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
		resumeKey:         id[:24],
		createOptions:     cr.CreateOptions(),
		fileAttributes:    smb2.FILE_ATTRIBUTE_NORMAL,
		lastModified:      time.Time(info.ModTime),
		size:              uint64(info.Size),
		allocated:         uint64(info.Size),
		ctx:               ctx,
		cancel:            cancel,
		lsaFrames:         make(map[uint32]*rpc.Frame),
		buffer:            make(map[uint64][]byte),
		chunkSize:         smb2.BytesPerSector * 4,
		maxCacheSize:      4,
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

// restoreOpen is invoked when a file created earlier during the session is mentioned again.
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

// closeOpen cancels all operations on the Open and destroys it.
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

// queryDirectory performs a search within the directory using the provided pattern.
// Wildcards are supported.
func (op *open) queryDirectory(pattern string) error {
	if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errNoDirectory
	}

	share := op.treeConnect.share
	objs, err := share.client.GetObjects(op.ctx, share.bucket, op.pathName+"/")
	if err != nil {
		return err
	}

	var results []api.ObjectMetadata
	for _, entry := range objs {
		_, name, _ := utils.ExtractFilename(entry.Key)
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

// id is a helper method that marshals the volatile and persistent ID parts into a byte sequence.
func (op *open) id() []byte {
	i := make([]byte, 16)
	binary.LittleEndian.PutUint64(i[:8], op.fileID)
	binary.LittleEndian.PutUint64(i[8:], op.durableFileID)
	return i
}

// fileAllInformation generates a FileAllInfo structure.
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

// fileStandardInformation generates a FileStandardInfo structure.
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

// fileNetworkOpenInformation genereates a FileNetworkOpenInfo structure.
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

// fileStreamInformation generates a FileStreamInfo structure.
func (op *open) fileStreamInformation() []byte {
	fsi := smb2.FileStreamInfo{
		StreamName:           "::$DATA",
		StreamSize:           op.size,
		StreamAllocationSize: op.allocated,
	}
	return fsi.Encode()
}

// newLSAFrame generates an LSA frame from the NTLM security context.
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

// checkForChanges monitors if any significant changes have occurred in the specified directory.
// Significant changes include: file names, sizes, modify times, or contents.
func (op *open) checkForChanges(req smb2.ChangeNotifyRequest, stopChan chan struct{}) {
	objs, err := op.treeConnect.share.client.GetObjects(op.ctx, op.treeConnect.share.bucket, op.pathName)
	if err != nil {
		return
	}

	snapshot := makeSnapshot(objs)
	for {
		select {
		case <-stopChan: // Execution terminated
			return
		case <-time.After(15 * time.Second): // Check every 15 seconds
		}

		objs, err := op.treeConnect.share.client.GetObjects(op.ctx, op.treeConnect.share.bucket, op.pathName)
		if err != nil {
			continue
		}

		newSnapshot := makeSnapshot(objs)
		if !bytes.Equal(newSnapshot, snapshot) {
			// Normally, the server should monitor the changes according to the filter specified in each
			// SMB2_CHANGE_NOTIFY request. If the WATCH_TREE flag is set, the server should also monitor
			// the entire directory tree underneath. This is a lot of effort. Fortunately, there is a
			// way to catch just any change and respond with the status STATUS_NOTIFY_ENUM_DIR, which
			// will simply trigger a rescan of the directory, exactly what we need.
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

// makeSnapshot takes a snapshot of the directory.
func makeSnapshot(entries []api.ObjectMetadata) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		h.Write([]byte(entry.ETag))
		h.Write([]byte(entry.ModTime.String()))
		h.Write([]byte(entry.Key))
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(entry.Size)))
	}

	return h.Sum(nil)
}

// getResumeKey is a helper method that generates a response to the FSCTL_SRV_REQUEST_RESUME_KEY query.
func (op *open) getResumeKey() []byte {
	key := make([]byte, 32)
	copy(key[:24], op.resumeKey)
	return key
}

// getObjectID is a helper method that generates a response to the FSCTL_CREATE_OR_GET_OBJECT_ID query.
func (op *open) getObjectID() []byte {
	id := make([]byte, 64)
	copy(id[:16], op.resumeKey[:16])
	binary.LittleEndian.PutUint64(id[16:24], op.treeConnect.share.volumeID)
	copy(id[32:48], op.resumeKey[:16])
	return id
}

// read checks if the requested chunk of data has already been downloaded. If so, it retrieves the data
// from the buffer. If not, it downloads it from the Sia network and caches it.
func (op *open) read(offset, length uint64) []byte {
	readData := func(o, l uint64) ([]byte, error) {
		var buf bytes.Buffer
		err := op.treeConnect.share.client.ReadObject(op.ctx, op.treeConnect.share.bucket, op.pathName, o, l, &buf)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	if offset >= op.size {
		return nil
	}

	if offset+length >= op.size {
		length = op.size - offset
	}

	var result []byte
	remaining := int64(length)

	for remaining > 0 {
		chunkOffset := (offset / op.chunkSize) * op.chunkSize
		chunkStart := offset % op.chunkSize
		chunkEnd := chunkStart + uint64(remaining)

		if chunkEnd > op.chunkSize {
			chunkEnd = op.chunkSize
		}

		if data, ok := op.buffer[chunkOffset]; ok {
			result = append(result, data[chunkStart:chunkEnd]...)
		} else {
			toRead := op.chunkSize
			if chunkOffset+toRead > op.size {
				toRead = op.size - chunkOffset
			}

			data, err := readData(chunkOffset, toRead)
			if err != nil {
				log.Println("Error reading object:", err)
				return nil
			}

			op.buffer[chunkOffset] = data
			op.cacheOrder = append(op.cacheOrder, chunkOffset)
			result = append(result, data[chunkStart:chunkEnd]...)
		}

		if len(op.buffer) > op.maxCacheSize {
			oldest := op.cacheOrder[0]
			delete(op.buffer, oldest)
			op.cacheOrder = op.cacheOrder[1:]
		}

		remaining -= int64(chunkEnd - chunkStart)
		offset += (chunkEnd - chunkStart)
	}

	return result
}
