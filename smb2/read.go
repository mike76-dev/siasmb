package smb2

import "encoding/binary"

const (
	SMB2ReadRequestMinSize       = 48
	SMB2ReadRequestStructureSize = 49

	SMB2ReadResponseMinSize       = 16
	SMB2ReadResponseStructureSize = 17
)

type ReadRequest struct {
	Request
}

func (rr ReadRequest) Validate() error {
	if err := Header(rr.data).Validate(); err != nil {
		return err
	}

	if len(rr.data) < SMB2HeaderSize+SMB2ReadRequestMinSize {
		return ErrWrongLength
	}

	if rr.structureSize() != SMB2ReadRequestStructureSize {
		return ErrWrongFormat
	}

	return nil
}

func (rr ReadRequest) Padding() uint8 {
	return rr.data[SMB2HeaderSize+2]
}

func (rr ReadRequest) Flags() uint8 {
	return rr.data[SMB2HeaderSize+3]
}

func (rr ReadRequest) Length() uint32 {
	return binary.LittleEndian.Uint32(rr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

func (rr ReadRequest) Offset() uint64 {
	return binary.LittleEndian.Uint64(rr.data[SMB2HeaderSize+8 : SMB2HeaderSize+16])
}

func (rr ReadRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, rr.data[SMB2HeaderSize+16:SMB2HeaderSize+32])
	return fid
}

func (rr ReadRequest) MinimumCount() uint32 {
	return binary.LittleEndian.Uint32(rr.data[SMB2HeaderSize+32 : SMB2HeaderSize+36])
}

type ReadResponse struct {
	Response
}

func (rr *ReadResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(rr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2ReadResponseStructureSize)
}

func (rr *ReadResponse) SetData(buf []byte, padding uint8) {
	if padding < SMB2HeaderSize+SMB2ReadResponseMinSize {
		return
	}
	rr.data[SMB2HeaderSize+2] = padding
	binary.LittleEndian.PutUint32(rr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(buf)))
	add := make([]byte, padding-SMB2HeaderSize-SMB2ReadResponseMinSize)
	rr.data = append(rr.data, add...)
	rr.data = append(rr.data, buf...)
}

func (rr *ReadResponse) FromRequest(req GenericRequest) {
	rr.Response.FromRequest(req)

	body := make([]byte, SMB2ReadResponseMinSize)
	rr.data = append(rr.data, body...)

	rr.setStructureSize()
	Header(rr.data).SetNextCommand(0)
	Header(rr.data).SetStatus(STATUS_OK)
	if Header(rr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(rr.data).SetCreditResponse(0)
	}
}

func (rr *ReadResponse) Generate(buf []byte, padding uint8) {
	rr.SetData(buf, padding)
}
