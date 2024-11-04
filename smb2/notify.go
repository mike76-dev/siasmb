package smb2

import "encoding/binary"

const (
	SMB2ChangeNotifyRequestMinSize       = 32
	SMB2ChangeNotifyRequestStructureSize = 32

	SMB2ChangeNotifyResponseMinSize       = 8
	SMB2ChangeNotifyResponseStructureSize = 9
)

const (
	WATCH_TREE = 0x0001
)

const (
	FILE_NOTIFY_CHANGE_FILE_NAME    = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME     = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES   = 0x00000004
	FILE_NOTIFY_CHANGE_SIZE         = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE   = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS  = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION     = 0x00000040
	FILE_NOTIFY_CHANGE_EA           = 0x00000080
	FILE_NOTIFY_CHANGE_SECURITY     = 0x00000100
	FILE_NOTIFY_CHANGE_STREAM_NAME  = 0x00000200
	FILE_NOTIFY_CHANGE_STREAM_SIZE  = 0x00000400
	FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800
)

type ChangeNotifyRequest struct {
	Request
}

func (cnr ChangeNotifyRequest) Validate() error {
	if err := Header(cnr.data).Validate(); err != nil {
		return err
	}

	if len(cnr.data) < SMB2HeaderSize+SMB2ChangeNotifyRequestMinSize {
		return ErrWrongLength
	}

	if cnr.structureSize() != SMB2ChangeNotifyRequestStructureSize {
		return ErrWrongFormat
	}

	return nil
}

func (cnr ChangeNotifyRequest) Flags() uint16 {
	return binary.LittleEndian.Uint16(cnr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
}

func (cnr ChangeNotifyRequest) OutputBufferLength() uint32 {
	return binary.LittleEndian.Uint32(cnr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

func (cnr ChangeNotifyRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, cnr.data[SMB2HeaderSize+8:SMB2HeaderSize+24])
	return fid
}

func (cnr ChangeNotifyRequest) CompletionFilter() uint32 {
	return binary.LittleEndian.Uint32(cnr.data[SMB2HeaderSize+24 : SMB2HeaderSize+28])
}

type ChangeNotifyResponse struct {
	Response
}

func (cnr *ChangeNotifyResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(cnr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2ChangeNotifyResponseStructureSize)
}

func (cnr *ChangeNotifyResponse) SetOutputBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(cnr.data[SMB2HeaderSize+2:SMB2HeaderSize+4], uint16(len(cnr.data)))
	binary.LittleEndian.PutUint32(cnr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(buf)))
	cnr.data = append(cnr.data, buf...)
}

func (cnr *ChangeNotifyResponse) FromRequest(req GenericRequest) {
	cnr.Response.FromRequest(req)

	body := make([]byte, SMB2ChangeNotifyResponseMinSize)
	cnr.data = append(cnr.data, body...)

	cnr.setStructureSize()
	Header(cnr.data).SetNextCommand(0)
	Header(cnr.data).SetStatus(STATUS_OK)
	if Header(cnr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(cnr.data).SetCreditResponse(0)
	} else {
		Header(cnr.data).SetCreditResponse(1)
	}
}

func (cnr *ChangeNotifyResponse) Generate(buf []byte) {
	cnr.SetOutputBuffer(buf)
}
