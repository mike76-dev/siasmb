package smb2

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/mike76-dev/siasmb/utils"
)

var (
	ErrNotSupported = errors.New("not supported")
)

const (
	SMB2CreateRequestMinSize       = 57
	SMB2CreateRequestStructureSize = 57

	SMB2CreateResponseMinSize       = 88
	SMB2CreateResponseStructureSize = 89
)

const (
	// Oplock level
	OPLOCK_LEVEL_NONE      = 0x00
	OPLOCK_LEVEL_II        = 0x01
	OPLOCK_LEVEL_EXCLUSIVE = 0x08
	OPLOCK_LEVEL_BATCH     = 0x09
	OPLOCK_LEVEL_LEASE     = 0xff
)

const (
	// Impersonation level
	IMPERSONATION_ANONYMOUS      = 0x00000000
	IMPERSONATION_IDENTIFICATION = 0x00000001
	IMPERSONATION_IMPERSONATION  = 0x00000002
	IMPERSONATION_DELEGATE       = 0x00000003
)

const (
	// Share access
	FILE_SHARE_READ   = 0x00000001
	FILE_SHARE_WRITE  = 0x00000002
	FILE_SHARE_DELETE = 0x00000004
)

const (
	// Create disposition
	FILE_SUPERSEDE    = 0x00000000
	FILE_OPEN         = 0x00000001
	FILE_CREATE       = 0x00000002
	FILE_OPEN_IF      = 0x00000003
	FILE_OVERWRITE    = 0x00000004
	FILE_OVERWRITE_IF = 0x00000005
)

const (
	// Create options
	FILE_DIRECTORY_FILE            = 0x00000001
	FILE_WRITE_THROUGH             = 0x00000002
	FILE_SEQUENTIAL_ONLY           = 0x00000004
	FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
	FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010
	FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020
	FILE_NON_DIRECTORY_FILE        = 0x00000040
	FILE_COMPLETE_IF_OPLOCKED      = 0x00000100
	FILE_NO_EA_KNOWLEDGE           = 0x00000200
	FILE_OPEN_REMOTE_INSTANCE      = 0x00000400
	FILE_RANDOM_ACCESS             = 0x00000800
	FILE_DELETE_ON_CLOSE           = 0x00001000
	FILE_OPEN_BY_FILE_ID           = 0x00002000
	FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000
	FILE_NO_COMPRESSION            = 0x00008000
	FILE_OPEN_REQUIRING_OPLOCK     = 0x00010000
	FILE_DISALLOW_EXCLUSIVE        = 0x00020000
	FILE_RESERVE_OPFILTER          = 0x00100000
	FILE_OPEN_REPARSE_POINT        = 0x00200000
	FILE_OPEN_NO_RECALL            = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
)

const (
	// File attributes
	FILE_ATTRIBUTE_READONLY              = 0x00000001
	FILE_ATTRIBUTE_HIDDEN                = 0x00000002
	FILE_ATTRIBUTE_SYSTEM                = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY             = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE               = 0x00000020
	FILE_ATTRIBUTE_NORMAL                = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY             = 0x00000100
	FILE_ATTRIBUTE_SPARSE_FILE           = 0x00000200
	FILE_ATTRIBUTE_REPARSE_POINT         = 0x00000400
	FILE_ATTRIBUTE_COMPRESSED            = 0x00000800
	FILE_ATTRIBUTE_OFFLINE               = 0x00001000
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   = 0x00002000
	FILE_ATTRIBUTE_ENCRYPTED             = 0x00004000
	FILE_ATTRIBUTE_INTEGRITY_STREAM      = 0x00008000
	FILE_ATTRIBUTE_NO_SCRUB_DATA         = 0x00020000
	FILE_ATTRIBUTE_RECALL_ON_OPEN        = 0x00040000
	FILE_ATTRIBUTE_PINNED                = 0x00080000
	FILE_ATTRIBUTE_UNPINNED              = 0x00100000
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
)

const (
	// Create context
	CREATE_EA_BUFFER                    = 0x45787441
	CREATE_SD_BUFFER                    = 0x53656344
	CREATE_DURABLE_HANDLE_REQUEST       = 0x44486e51
	CREATE_DURABLE_HANDLE_RECONNECT     = 0x44486e43
	CREATE_ALLOCATION_SIZE              = 0x416c5369
	CREATE_QUERY_MAXIMAL_ACCESS_REQUEST = 0x4d784163
	CREATE_TIMEWAROP_TOKEN              = 0x54577270
	CREATE_QUERY_ON_DISK_ID             = 0x51466964
	CREATE_REQUEST_LEASE                = 0x52714c73
)

const (
	OplockNone int = iota
	OplockHeld
	OplockBreaking
)

const (
	// Create action
	FILE_SUPERSEDED  = 0x00000000
	FILE_OPENED      = 0x00000001
	FILE_CREATED     = 0x00000002
	FILE_OVERWRITTEN = 0x00000003
)

const (
	clusterSize = uint64(4 * 1024 * 1024)
)

type CreateRequest struct {
	Request
}

func (cr CreateRequest) Validate() error {
	if err := Header(cr.data).Validate(); err != nil {
		return err
	}

	if len(cr.data) < SMB2HeaderSize+SMB2CreateRequestMinSize {
		return ErrWrongLength
	}

	if cr.structureSize() != SMB2CreateRequestStructureSize {
		return ErrWrongFormat
	}

	cd := cr.CreateDisposition()
	co := cr.CreateOptions()
	if co&uint32(FILE_DIRECTORY_FILE) > 0 {
		if cd != FILE_CREATE && cd != FILE_OPEN && cd != FILE_OPEN_IF {
			return ErrInvalidParameter
		}

		if co & ^uint32(FILE_DIRECTORY_FILE) &
			^uint32(FILE_WRITE_THROUGH) &
			^uint32(FILE_OPEN_FOR_BACKUP_INTENT) &
			^uint32(FILE_DELETE_ON_CLOSE) &
			^uint32(FILE_OPEN_REPARSE_POINT) > 0 {
			return ErrInvalidParameter
		}

		if co&uint32(FILE_OPEN_BY_FILE_ID) > 0 || co&uint32(FILE_RESERVE_OPFILTER) > 0 {
			return ErrNotSupported
		}
	}

	off := binary.LittleEndian.Uint16(cr.data[SMB2HeaderSize+44 : SMB2HeaderSize+46])
	length := binary.LittleEndian.Uint16(cr.data[SMB2HeaderSize+46 : SMB2HeaderSize+48])
	if off%8 > 0 || length%2 > 0 || off+length > uint16(len(cr.data)) {
		return ErrInvalidParameter
	}

	cOff := binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+48 : SMB2HeaderSize+52])
	cLength := binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+52 : SMB2HeaderSize+56])
	if cOff+cLength > uint32(len(cr.data)) {
		return ErrInvalidParameter
	}

	return nil
}

func (cr CreateRequest) RequestedOplockLevel() uint8 {
	return cr.data[SMB2HeaderSize+3]
}

func (cr CreateRequest) ImpersonationLevel() uint32 {
	return binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

func (cr CreateRequest) DesiredAccess() uint32 {
	return binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+24 : SMB2HeaderSize+28])
}

func (cr *CreateRequest) SetDesiredAccess(da uint32) {
	binary.LittleEndian.PutUint32(cr.data[SMB2HeaderSize+24:SMB2HeaderSize+28], da)
}

func (cr CreateRequest) FileAttributes() uint32 {
	return binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+28 : SMB2HeaderSize+32])
}

func (cr CreateRequest) ShareAccess() uint32 {
	return binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+32 : SMB2HeaderSize+36])
}

func (cr CreateRequest) CreateDisposition() uint32 {
	return binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+36 : SMB2HeaderSize+40])
}

func (cr CreateRequest) CreateOptions() uint32 {
	return binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+40 : SMB2HeaderSize+44])
}

func (cr *CreateRequest) SetCreateOptions(options uint32) {
	binary.LittleEndian.PutUint32(cr.data[SMB2HeaderSize+40:SMB2HeaderSize+44], options)
}

func (cr CreateRequest) CreateOptionSelected(option uint32) bool {
	return cr.CreateOptions()&option > 0
}

func (cr CreateRequest) Filename() string {
	off := binary.LittleEndian.Uint16(cr.data[SMB2HeaderSize+44 : SMB2HeaderSize+46])
	length := binary.LittleEndian.Uint16(cr.data[SMB2HeaderSize+46 : SMB2HeaderSize+48])
	return utils.DecodeToString(cr.data[off : off+length])
}

func (cr CreateRequest) CreateContexts() (map[uint32][]byte, error) {
	off := binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+48 : SMB2HeaderSize+52])
	length := binary.LittleEndian.Uint32(cr.data[SMB2HeaderSize+52 : SMB2HeaderSize+56])
	if length < 4 {
		return nil, nil
	}

	contexts := make(map[uint32][]byte)
	for off < uint32(len(cr.data)) {
		next := binary.LittleEndian.Uint32(cr.data[off : off+4])

		nameOff := uint32(binary.LittleEndian.Uint16(cr.data[off+4 : off+6]))
		nameLen := binary.LittleEndian.Uint16(cr.data[off+6 : off+8])
		if nameLen > 4 {
			off += next
			if next == 0 {
				break
			}
			continue
		} else if nameLen < 4 {
			return nil, ErrInvalidParameter
		}

		name := binary.BigEndian.Uint32(cr.data[off+nameOff : off+nameOff+4])
		dataOff := uint32(binary.LittleEndian.Uint16(cr.data[off+10 : off+12]))
		dataLen := binary.LittleEndian.Uint32(cr.data[off+12 : off+16])
		data := make([]byte, dataLen)
		copy(data, cr.data[off+dataOff:off+dataOff+dataLen])
		contexts[name] = data

		off += next
		if next == 0 {
			break
		}
	}

	return contexts, nil
}

type CreateResponse struct {
	Response
}

func (cr *CreateResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(cr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2CreateResponseStructureSize)
}

func (cr *CreateResponse) SetOplockLevel(ol uint8) {
	cr.data[SMB2HeaderSize+2] = ol
}

func (cr *CreateResponse) SetCreateAction(ca uint32) {
	binary.LittleEndian.PutUint32(cr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], ca)
}

func (cr *CreateResponse) SetFileTime(creation, lastAccess, lastWrite, change time.Time) {
	binary.LittleEndian.PutUint64(cr.data[SMB2HeaderSize+8:SMB2HeaderSize+16], utils.UnixToFiletime(creation))
	binary.LittleEndian.PutUint64(cr.data[SMB2HeaderSize+16:SMB2HeaderSize+24], utils.UnixToFiletime(lastAccess))
	binary.LittleEndian.PutUint64(cr.data[SMB2HeaderSize+24:SMB2HeaderSize+32], utils.UnixToFiletime(lastWrite))
	binary.LittleEndian.PutUint64(cr.data[SMB2HeaderSize+32:SMB2HeaderSize+40], utils.UnixToFiletime(change))
}

func (cr *CreateResponse) SetFilesize(size uint64) {
	allocated := (size + (clusterSize - 1)) &^ (clusterSize - 1)
	binary.LittleEndian.PutUint64(cr.data[SMB2HeaderSize+40:SMB2HeaderSize+48], size)
	binary.LittleEndian.PutUint64(cr.data[SMB2HeaderSize+48:SMB2HeaderSize+56], allocated)
}

func (cr *CreateResponse) SetFileAttributes(fa uint32) {
	binary.LittleEndian.PutUint32(cr.data[SMB2HeaderSize+56:SMB2HeaderSize+60], fa)
}

func (cr *CreateResponse) SetFileID(fid []byte) {
	copy(cr.data[SMB2HeaderSize+64:SMB2HeaderSize+80], fid)
}

func (cr *CreateResponse) SetCreateContexts(contexts map[uint32][]byte) {
	length := len(contexts)
	if length == 0 {
		return
	}

	var buf []byte
	var count int
	for id, ctx := range contexts {
		ctxLen := 24 + len(ctx)
		if count < length-1 {
			ctxLen = utils.Roundup(ctxLen, 8)
		}

		context := make([]byte, ctxLen)
		if count < length-1 {
			binary.LittleEndian.PutUint32(context[:4], uint32(ctxLen))
		}

		binary.LittleEndian.PutUint16(context[4:6], 16)
		binary.LittleEndian.PutUint16(context[6:8], 4)
		binary.BigEndian.PutUint32(context[16:20], id)

		binary.LittleEndian.PutUint16(context[10:12], 24)
		binary.LittleEndian.PutUint32(context[12:16], uint32(len(ctx)))
		copy(context[24:24+len(ctx)], ctx)

		buf = append(buf, context...)
		count++
	}

	binary.LittleEndian.PutUint32(cr.data[SMB2HeaderSize+80:SMB2HeaderSize+84], SMB2HeaderSize+88)
	binary.LittleEndian.PutUint32(cr.data[SMB2HeaderSize+84:SMB2HeaderSize+88], uint32(len(buf)))
	cr.data = append(cr.data, buf...)
}

func (cr *CreateResponse) FromRequest(req GenericRequest) {
	cr.Response.FromRequest(req)

	body := make([]byte, SMB2CreateResponseMinSize)
	cr.data = append(cr.data, body...)

	cr.setStructureSize()
	Header(cr.data).SetNextCommand(0)
	Header(cr.data).SetStatus(STATUS_OK)
	if Header(cr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(cr.data).SetCreditResponse(0)
	} else {
		Header(cr.data).SetCreditResponse(1)
	}
}

func (cr *CreateResponse) Generate(
	oplockLevel uint8,
	createAction uint32,
	size uint64,
	modTime time.Time,
	isDir bool,
	fileID uint64,
	durableFileID uint64,
	createContexts map[uint32][]byte,
) {
	cr.SetOplockLevel(oplockLevel)
	cr.SetCreateAction(createAction)

	var creationTime, lastAccessTime, lastWriteTime, changeTime time.Time
	now := time.Now()
	switch createAction {
	case FILE_SUPERSEDED, FILE_CREATED:
		creationTime = now
		lastAccessTime = now
		lastWriteTime = now
		changeTime = now
	case FILE_OPENED:
		creationTime = modTime
		lastAccessTime = now
		lastWriteTime = modTime
		changeTime = modTime
	case FILE_OVERWRITTEN:
		creationTime = modTime
		lastAccessTime = now
		lastWriteTime = now
		changeTime = now
	}

	cr.SetFileTime(creationTime, lastAccessTime, lastWriteTime, changeTime)

	if isDir {
		cr.SetFileAttributes(FILE_ATTRIBUTE_DIRECTORY)
	} else {
		cr.SetFileAttributes(FILE_ATTRIBUTE_NORMAL)
		cr.SetFilesize(size)
	}

	fid := make([]byte, 16)
	binary.LittleEndian.PutUint64(fid[:8], fileID)
	binary.LittleEndian.PutUint64(fid[8:], durableFileID)
	cr.SetFileID(fid)

	cr.SetCreateContexts(createContexts)
}

func HandleCreateQueryMaximalAccessRequest(ctx []byte, modTime time.Time, maxAccess uint32) []byte {
	resp := make([]byte, 8)
	if len(ctx) != 8 {
		binary.LittleEndian.PutUint32(resp[:4], STATUS_OK)
		binary.LittleEndian.PutUint32(resp[4:], maxAccess)
	} else {
		timestamp := utils.FiletimeToUnix(binary.LittleEndian.Uint64(ctx[:8]))
		if timestamp == modTime {
			binary.LittleEndian.PutUint32(resp[:4], STATUS_NONE_MAPPED)
		} else {
			binary.LittleEndian.PutUint32(resp[:4], STATUS_OK)
			binary.LittleEndian.PutUint32(resp[4:], maxAccess)
		}
	}
	return resp
}

func HandleCreateQueryOnDiskID(fid, vid uint64) []byte {
	resp := make([]byte, 32)
	binary.LittleEndian.PutUint64(resp[:8], fid)
	binary.LittleEndian.PutUint64(resp[8:16], vid)
	return resp
}

func HandleCreateDurableHandleRequest() []byte {
	resp := make([]byte, 8)
	return resp
}
