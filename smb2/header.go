package smb2

import (
	"encoding/binary"
	"errors"
)

const (
	PROTOCOL_SMB             = 0x424d53ff
	PROTOCOL_SMB2            = 0x424d53fe
	PROTOCOL_SMB2_ENCRYPTED  = 0x424d53fd
	PROTOCOL_SMB2_COMPRESSED = 0x424d53fc
)

const (
	SMB_COM_NEGOTIATE = 0x72

	SMB2_NEGOTIATE                     = 0x0000
	SMB2_SESSION_SETUP                 = 0x0001
	SMB2_LOGOFF                        = 0x0002
	SMB2_TREE_CONNECT                  = 0x0003
	SMB2_TREE_DISCONNECT               = 0x0004
	SMB2_CREATE                        = 0x0005
	SMB2_CLOSE                         = 0x0006
	SMB2_FLUSH                         = 0x0007
	SMB2_READ                          = 0x0008
	SMB2_WRITE                         = 0x0009
	SMB2_LOCK                          = 0x000a
	SMB2_IOCTL                         = 0x000b
	SMB2_CANCEL                        = 0x000c
	SMB2_ECHO                          = 0x000d
	SMB2_QUERY_DIRECTORY               = 0x000e
	SMB2_CHANGE_NOTIFY                 = 0x000f
	SMB2_QUERY_INFO                    = 0x0010
	SMB2_SET_INFO                      = 0x0011
	SMB2_OPLOCK_BREAK                  = 0x0012
	SMB2_SERVER_TO_CLIENT_NOTIFICATION = 0x0013
)

const (
	FLAGS_SERVER_TO_REDIR    = 0x00000001
	FLAGS_ASYNC_COMMAND      = 0x00000002
	FLAGS_RELATED_OPERATIONS = 0x00000004
	FLAGS_SIGNED             = 0x00000008
	FLAGS_PRIORITY_MASK      = 0x00000070
	FLAGS_DFS_OPERATIONS     = 0x10000000
	FLAGS_REPLAY_OPERATION   = 0x20000000
)

var (
	ErrEncryptedMessage  = errors.New("message encryption not supported")
	ErrCompressedMessage = errors.New("message compression not supported")
	ErrWrongLength       = errors.New("wrong data length")
	ErrWrongFormat       = errors.New("wrong data format")
	ErrWrongProtocol     = errors.New("unsupported protocol")
)

const (
	SMBHeaderSize  = 32
	SMB2HeaderSize = 64

	SMB2HeaderStructureSize = 64
)

type Header []byte

func NewHeader(data []byte) Header {
	binary.LittleEndian.PutUint32(data[:4], PROTOCOL_SMB2)
	binary.LittleEndian.PutUint16(data[4:6], SMB2HeaderStructureSize)
	return Header(data)
}

func (h Header) CopyFrom(src Header) {
	copy(h[:SMB2HeaderSize], src[:SMB2HeaderSize])
}

func (h Header) IsSmb() bool {
	return binary.LittleEndian.Uint32(h[:4]) == PROTOCOL_SMB
}

func (h Header) IsSmb2() bool {
	id := binary.LittleEndian.Uint32(h[:4])
	return id == PROTOCOL_SMB2 || id == PROTOCOL_SMB2_ENCRYPTED || id == PROTOCOL_SMB2_COMPRESSED
}

func (h Header) Validate() error {
	if len(h) < 4 {
		return ErrWrongLength
	}

	if h.IsSmb() {
		if len(h) < SMBHeaderSize {
			return ErrWrongLength
		}

		if h.LegacyCommand() != SMB_COM_NEGOTIATE {
			return ErrWrongProtocol
		}

		return nil
	}

	if h.IsSmb2() {
		if len(h) < SMB2HeaderSize {
			return ErrWrongLength
		}

		id := binary.LittleEndian.Uint32(h[:4])
		if id == PROTOCOL_SMB2_ENCRYPTED {
			return ErrEncryptedMessage
		}
		if id == PROTOCOL_SMB2_COMPRESSED {
			return ErrCompressedMessage
		}

		if binary.LittleEndian.Uint16(h[4:6]) != SMB2HeaderStructureSize {
			return ErrWrongFormat
		}

		return nil
	}

	return ErrWrongProtocol
}

func (h Header) LegacyCommand() uint8 {
	return h[4]
}

func (h Header) CreditCharge() uint16 {
	return binary.LittleEndian.Uint16(h[6:8])
}

func (h Header) SetCreditCharge(cc uint16) {
	binary.LittleEndian.PutUint16(h[6:8], cc)
}

func (h Header) Status() uint32 {
	return binary.LittleEndian.Uint32(h[8:12])
}

func (h Header) SetStatus(status uint32) {
	binary.LittleEndian.PutUint32(h[8:12], status)
}

func (h Header) Command() uint16 {
	return binary.LittleEndian.Uint16(h[12:14])
}

func (h Header) SetCommand(command uint16) {
	binary.LittleEndian.PutUint16(h[12:14], command)
}

func (h Header) CreditRequest() uint16 {
	return binary.LittleEndian.Uint16(h[14:16])
}

func (h Header) SetCreditResponse(cr uint16) {
	binary.LittleEndian.PutUint16(h[14:16], cr)
}

func (h Header) Flags() uint32 {
	return binary.LittleEndian.Uint32(h[16:20])
}

func (h Header) SetFlags(flags uint32) {
	binary.LittleEndian.PutUint32(h[16:20], flags)
}

func (h Header) IsFlagSet(flag uint32) bool {
	return h.Flags()&flag > 0
}

func (h Header) SetFlag(flag uint32) {
	h.SetFlags(h.Flags() | flag)
}

func (h Header) ClearFlag(flag uint32) {
	h.SetFlags(h.Flags() &^ flag)
}

func (h Header) NextCommand() uint32 {
	return binary.LittleEndian.Uint32(h[20:24])
}

func (h Header) SetNextCommand(nc uint32) {
	binary.LittleEndian.PutUint32(h[20:24], nc)
}

func (h Header) MessageID() uint64 {
	return binary.LittleEndian.Uint64(h[24:32])
}

func (h Header) SetMessageID(mid uint64) {
	binary.LittleEndian.PutUint64(h[24:32], mid)
}

func (h Header) AsyncID() uint64 {
	return binary.LittleEndian.Uint64(h[32:40])
}

func (h Header) SetAsyncID(aid uint64) {
	binary.LittleEndian.PutUint64(h[32:40], aid)
}

func (h Header) TreeID() uint32 {
	return binary.LittleEndian.Uint32(h[36:40])
}

func (h Header) SetTreeID(tid uint32) {
	binary.LittleEndian.PutUint32(h[36:40], tid)
}

func (h Header) SessionID() uint64 {
	return binary.LittleEndian.Uint64(h[40:48])
}

func (h Header) SetSessionID(sid uint64) {
	binary.LittleEndian.PutUint64(h[40:48], sid)
}

func (h Header) Signature() []byte {
	return h[48:64]
}

func (h Header) SetSignature(signature []byte) {
	copy(h[48:64], signature)
}

func (h Header) WipeSignature() {
	var zero [16]byte
	h.SetSignature(zero[:])
}
