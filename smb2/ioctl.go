package smb2

import "encoding/binary"

const (
	SMB2IoctlRequestMinSize       = 56
	SMB2IoctlRequestStructureSize = 57

	SMB2IoctlResponseMinSize       = 48
	SMB2IoctlResponseStructureSize = 49
)

const (
	FSCTL_DFS_GET_REFERRALS            = 0x00060194
	FSCTL_PIPE_PEEK                    = 0x0011400c
	FSCTL_PIPE_WAIT                    = 0x00110018
	FSCTL_PIPE_TRANSCEIVE              = 0x0011c017
	FSCTL_SRV_COPYCHUNK                = 0x001440f2
	FSCTL_SRV_ENUMERATE_SNAPSHOTS      = 0x00144064
	FSCTL_SRV_REQUEST_RESUME_KEY       = 0x00140078
	FSCTL_SRV_READ_HASH                = 0x001441bb
	FSCTL_SRV_COPYCHUNK_WRITE          = 0x001480f2
	FSCTL_LMR_REQUEST_RESILIENCY       = 0x001401d4
	FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401fc
	FSCTL_SET_REPARSE_POINT            = 0x000900a4
	FSCTL_DFS_GET_REFERRALS_EX         = 0x000601b0
	FSCTL_FILE_LEVEL_TRIM              = 0x00098208
	FSCTL_VALIDATE_NEGOTIATE_INFO      = 0x00140204
	FSCTL_CREATE_OR_GET_OBJECT_ID      = 0x000900c0
)

const (
	IOCTL_IS_FSCTL = 0x00000001
)

var (
	DummyFileID = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type IoctlRequest struct {
	Request
}

func (ir IoctlRequest) Validate() error {
	if err := Header(ir.data).Validate(); err != nil {
		return err
	}

	if len(ir.data) < SMB2HeaderSize+SMB2IoctlRequestMinSize {
		return ErrWrongLength
	}

	if ir.structureSize() != SMB2IoctlRequestStructureSize {
		return ErrWrongFormat
	}

	off := binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+24 : SMB2HeaderSize+28])
	length := binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+28 : SMB2HeaderSize+32])
	if length > 0 && ((off > 0 && off < SMB2HeaderSize+SMB2IoctlRequestMinSize) || off%8 > 0 || off+length > uint32(len(ir.data))) {
		return ErrInvalidParameter
	}

	return nil
}

func (ir IoctlRequest) CtlCode() uint32 {
	return binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

func (ir IoctlRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, ir.data[SMB2HeaderSize+8:SMB2HeaderSize+24])
	return fid
}

func (ir IoctlRequest) InputBuffer() []byte {
	off := binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+24 : SMB2HeaderSize+28])
	length := binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+28 : SMB2HeaderSize+32])
	if len(ir.data) < int(off+length) {
		return nil
	}
	return ir.data[off : off+length]
}

func (ir IoctlRequest) MaxInputResponse() uint32 {
	return binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+32 : SMB2HeaderSize+36])
}

func (ir IoctlRequest) MaxOutputResponse() uint32 {
	return binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+44 : SMB2HeaderSize+48])
}

func (ir IoctlRequest) Flags() uint32 {
	return binary.LittleEndian.Uint32(ir.data[SMB2HeaderSize+48 : SMB2HeaderSize+52])
}

type IoctlResponse struct {
	Response
}

func (ir *IoctlResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(ir.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2IoctlResponseStructureSize)
}

func (ir *IoctlResponse) SetCtlCode(code uint32) {
	binary.LittleEndian.PutUint32(ir.data[SMB2HeaderSize+4:SMB2HeaderSize+8], code)
}

func (ir *IoctlResponse) SetFileID(fid []byte) {
	copy(ir.data[SMB2HeaderSize+8:SMB2HeaderSize+24], fid)
}

func (ir *IoctlResponse) SetFlags(flags uint32) {
	binary.LittleEndian.PutUint32(ir.data[SMB2HeaderSize+40:SMB2HeaderSize+44], flags)
}

func (ir *IoctlResponse) SetOutputBuffer(buf []byte) {
	binary.LittleEndian.PutUint32(ir.data[SMB2HeaderSize+24:SMB2HeaderSize+28], SMB2HeaderSize+SMB2IoctlResponseMinSize)
	binary.LittleEndian.PutUint32(ir.data[SMB2HeaderSize+28:SMB2HeaderSize+32], 0)
	var off uint32
	if len(buf) > 0 {
		off = uint32(SMB2HeaderSize + SMB2IoctlResponseMinSize)
	}
	binary.LittleEndian.PutUint32(ir.data[SMB2HeaderSize+32:SMB2HeaderSize+36], off)
	binary.LittleEndian.PutUint32(ir.data[SMB2HeaderSize+36:SMB2HeaderSize+40], uint32(len(buf)))
	ir.data = ir.data[:SMB2HeaderSize+SMB2IoctlResponseMinSize]
	ir.data = append(ir.data, buf...)
}

func (ir *IoctlResponse) FromRequest(req GenericRequest) {
	ir.Response.FromRequest(req)

	body := make([]byte, SMB2IoctlResponseMinSize)
	ir.data = append(ir.data, body...)

	ir.setStructureSize()
	Header(ir.data).SetNextCommand(0)
	Header(ir.data).SetStatus(STATUS_OK)
	if Header(ir.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(ir.data).SetCreditResponse(0)
	}
}

func (ir *IoctlResponse) Generate(code uint32, fid []byte, flags uint32, output []byte) {
	ir.SetCtlCode(code)
	ir.SetFileID(fid)
	ir.SetFlags(flags)
	ir.SetOutputBuffer(output)
}
