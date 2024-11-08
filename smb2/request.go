package smb2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/mike76-dev/siasmb/utils"
)

var (
	ErrRelatedRequests   = errors.New("first request in a chain cannot be related")
	ErrMixedRequests     = errors.New("wrong usage of the related flag")
	ErrUnalignedRequests = errors.New("chained requests must be aligned to a 8-byte boundary")
)

const (
	SMB2CancelRequestMinSize       = 4
	SMB2CancelRequestStructureSize = 4
)

type GenericRequest interface {
	Validate() error
	Header() Header
	CancelRequestID() uint64
	GroupID() uint64
	OpenID() []byte
}

type Request struct {
	cancelRequestID uint64
	groupID         uint64
	data            []byte
	openID          []byte
}

func (req Request) structureSize() uint16 {
	if Header(req.data).IsSmb() {
		return 0
	}

	return binary.LittleEndian.Uint16(req.data[SMB2HeaderSize : SMB2HeaderSize+2])
}

func GetRequests(data []byte, cid uint64) (reqs []*Request, err error) {
	req := &Request{
		cancelRequestID: cid,
		data:            data,
	}

	if err := req.Header().Validate(); err != nil {
		return nil, err
	}

	next := req.Header().NextCommand()
	if next == 0 {
		return []*Request{req}, nil
	}

	var off uint32
	var related bool
	for {
		if next&7 > 0 {
			return nil, ErrUnalignedRequests
		}

		if off == 0 && req.Header().IsFlagSet(FLAGS_RELATED_OPERATIONS) {
			return nil, ErrRelatedRequests
		}

		if len(reqs) > 1 && ((!related && req.Header().IsFlagSet(FLAGS_RELATED_OPERATIONS)) || (related && !req.Header().IsFlagSet(FLAGS_RELATED_OPERATIONS))) {
			return nil, ErrMixedRequests
		}

		if req.Header().IsFlagSet(FLAGS_RELATED_OPERATIONS) {
			related = true
		}

		if next > 0 {
			req.data = data[off : off+next]
		}

		reqs = append(reqs, req)
		if next == 0 {
			break
		}

		off += next
		req = &Request{
			cancelRequestID: cid,
			data:            data[off:],
		}

		if err := req.Header().Validate(); err != nil {
			return nil, err
		}

		next = req.Header().NextCommand()
	}

	if related {
		gid := make([]byte, 8)
		rand.Read(gid)
		groupID := binary.LittleEndian.Uint64(gid)
		for _, req := range reqs {
			req.groupID = groupID
		}
	}

	return
}

func (req Request) Validate() error {
	return req.Header().Validate()
}

func (req Request) Header() Header {
	return Header(req.data)
}

func (req Request) CancelRequestID() uint64 {
	return req.cancelRequestID
}

func (req Request) GroupID() uint64 {
	return req.groupID
}

func (req Request) OpenID() []byte {
	return req.openID
}

func (req *Request) SetOpenID(id []byte) {
	req.openID = make([]byte, 16)
	copy(req.openID, id)
}

type GenericResponse interface {
	FromRequest(req GenericRequest)
	EncodedLength() int
	Encode() []byte
	Header() Header
	GroupID() uint64
	SessionID() uint64
	SetSessionID(id uint64)
	TreeID() uint32
	SetTreeID(id uint32)
	OpenID() []byte
	SetOpenID(id []byte)
	Append(newResp GenericResponse)
	CreditResponse() (lastMessageID uint64, lastCreditResponse uint16)
}

type Response struct {
	data      []byte
	groupID   uint64
	sessionID uint64
	treeID    uint32
	openID    []byte
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

func (resp Response) GroupID() uint64 {
	return resp.groupID
}

func (resp Response) SessionID() uint64 {
	return resp.sessionID
}

func (resp *Response) SetSessionID(id uint64) {
	resp.sessionID = id
}

func (resp Response) TreeID() uint32 {
	return resp.treeID
}

func (resp *Response) SetTreeID(id uint32) {
	resp.treeID = id
}

func (resp Response) OpenID() []byte {
	return resp.openID
}

func (resp *Response) SetOpenID(id []byte) {
	resp.openID = make([]byte, 16)
	copy(resp.openID, id)
}

func (resp *Response) FromRequest(req GenericRequest) {
	resp.data = make([]byte, SMB2HeaderSize)
	Header(resp.data).CopyFrom(req.Header())
	Header(resp.data).SetStatus(STATUS_OK)
	Header(resp.data).SetFlag(FLAGS_SERVER_TO_REDIR)
	if req.GroupID() == 0 {
		Header(resp.data).ClearFlag(FLAGS_RELATED_OPERATIONS)
	}
	resp.groupID = req.GroupID()
}

func (resp *Response) Append(newResp GenericResponse) {
	var off uint32
	for {
		next := binary.LittleEndian.Uint32(resp.data[off+20 : off+24])
		if next == 0 {
			break
		}
		off += next
	}

	newLen := utils.Roundup(len(resp.data), 8)
	if newLen > len(resp.data) {
		buf := make([]byte, newLen-len(resp.data))
		resp.data = append(resp.data, buf...)
	}

	binary.LittleEndian.PutUint32(resp.data[off+20:off+24], uint32(newLen)-off)
	newResp.Header().SetFlag(FLAGS_RELATED_OPERATIONS)
	resp.data = append(resp.data, newResp.Encode()...)
}

func (resp *Response) CreditResponse() (lastMessageID uint64, lastCreditResponse uint16) {
	h := resp.Header()
	var off uint32
	for {
		lastMessageID = h.MessageID()
		lastCreditResponse = h.CreditRequest()
		next := h.NextCommand()
		if next == 0 {
			break
		}

		off += next
		h = Header(resp.data[off:])
	}

	return
}

type CancelRequest struct {
	Request
}

func (cr CancelRequest) Validate() error {
	if err := Header(cr.data).Validate(); err != nil {
		return err
	}

	if len(cr.data) < SMB2HeaderSize+SMB2CancelRequestMinSize {
		return ErrWrongLength
	}

	if cr.structureSize() != SMB2CancelRequestStructureSize {
		return ErrWrongFormat
	}

	return nil
}
