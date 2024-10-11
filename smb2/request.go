package smb2

import (
	"encoding/binary"
)

type GenericRequest interface {
	Validate() error
	Header() Header
	CancelRequestID() uint64
}

type Request struct {
	cancelRequestID uint64
	data            []byte
}

func (req Request) structureSize() uint16 {
	if Header(req.data).IsSmb() {
		return 0
	}

	return binary.LittleEndian.Uint16(req.data[SMB2HeaderSize : SMB2HeaderSize+2])
}

func NewRequest(data []byte, cid uint64) *Request {
	return &Request{
		cancelRequestID: cid,
		data:            data,
	}
}

func (req Request) Header() Header {
	return Header(req.data)
}

func (req Request) CancelRequestID() uint64 {
	return req.cancelRequestID
}

type GenericResponse interface {
	FromRequest(req GenericRequest)
	EncodedLength() int
	Encode() []byte
	Header() Header
}

type Response struct {
	data []byte
}

func (resp Response) EncodedLength() int {
	return len(resp.data)
}

func (resp Response) Encode() []byte {
	return resp.data
}

func (resp Response) Header() Header {
	return Header(resp.data)
}

func (resp *Response) FromRequest(req GenericRequest) {
	resp.data = make([]byte, SMB2HeaderSize)
	Header(resp.data).CopyFrom(req.Header())
	Header(resp.data).SetStatus(STATUS_OK)
	Header(resp.data).SetFlag(FLAGS_SERVER_TO_REDIR)
}
