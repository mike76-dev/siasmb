package smb2

import "encoding/binary"

const (
	SMB2WriteRequestMinSize       = 48
	SMB2WriteRequestStructureSize = 49

	SMB2WriteResponseMinSize       = 16
	SMB2WriteResponseStructureSize = 17
)

type WriteRequest struct {
	Request
}

func (wr WriteRequest) Validate() error {
	if err := Header(wr.data).Validate(); err != nil {
		return err
	}

	if len(wr.data) < SMB2HeaderSize+SMB2WriteRequestMinSize {
		return ErrWrongLength
	}

	if wr.structureSize() != SMB2WriteRequestStructureSize {
		return ErrWrongFormat
	}

	off := binary.LittleEndian.Uint16(wr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
	length := binary.LittleEndian.Uint32(wr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
	if uint32(off)+length > uint32(len(wr.data)) {
		return ErrInvalidParameter
	}

	return nil
}

func (wr WriteRequest) Offset() uint64 {
	return binary.LittleEndian.Uint64(wr.data[SMB2HeaderSize+8 : SMB2HeaderSize+16])
}

func (wr WriteRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, wr.data[SMB2HeaderSize+16:SMB2HeaderSize+32])
	return fid
}

func (wr WriteRequest) Flags() uint32 {
	return binary.LittleEndian.Uint32(wr.data[SMB2HeaderSize+44 : SMB2HeaderSize+48])
}

func (wr WriteRequest) Buffer() []byte {
	off := binary.LittleEndian.Uint16(wr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
	length := binary.LittleEndian.Uint32(wr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
	return wr.data[uint32(off) : uint32(off)+length]
}

type WriteResponse struct {
	Response
}

func (wr *WriteResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(wr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2WriteResponseStructureSize)
}

func (wr *WriteResponse) SetCount(count uint32) {
	binary.LittleEndian.PutUint32(wr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], count)
}

func (wr *WriteResponse) FromRequest(req GenericRequest) {
	wr.Response.FromRequest(req)

	body := make([]byte, SMB2WriteResponseMinSize)
	wr.data = append(wr.data, body...)

	wr.setStructureSize()
	Header(wr.data).SetNextCommand(0)
	Header(wr.data).SetStatus(STATUS_OK)
	if Header(wr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(wr.data).SetCreditResponse(0)
	}
}

func (wr *WriteResponse) Generate(count uint32) {
	wr.SetCount(count)
}
