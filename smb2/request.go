package smb2

import (
	"encoding/binary"
)

type GenericRequest interface {
	Validate() error
	Header() *Header
	CancelRequestID() uint64
}

type Request struct {
	header          *Header
	cancelRequestID uint64
	data            []byte
}

func (req *Request) structureSize() uint16 {
	if req.header.IsSmb() {
		return 0
	}

	return binary.LittleEndian.Uint16(req.data[SMB2HeaderSize : SMB2HeaderSize+2])
}

func NewRequest(data []byte, cid uint64) *Request {
	return &Request{
		header:          NewHeader(data),
		cancelRequestID: cid,
		data:            data,
	}
}

func (req *Request) Header() *Header {
	return req.header
}

func (req *Request) CancelRequestID() uint64 {
	return req.cancelRequestID
}

type GenericResponse interface {
	FromRequest(req GenericRequest)
	EncodedLength() int
}

type Response struct {
	header *Header
	data   []byte
}

func (resp *Response) EncodedLength() int {
	return len(resp.data)
}

func (resp *Response) FromRequest(req GenericRequest) {
	resp.data = make([]byte, SMB2HeaderSize)
	resp.header = GetHeader(resp.data)
	resp.header.CopyFrom(req.Header())
	resp.header.SetStatus(STATUS_OK)
	resp.header.SetFlag(FLAGS_SERVER_TO_REDIR)
}
