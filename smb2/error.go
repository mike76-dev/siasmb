package smb2

import (
	"encoding/binary"
)

const (
	SMB2ErrorResponseMinSize       = 8
	SMB2ErrorResponseStructureSize = 9
)

const (
	STATUS_OK                       = 0x00000000
	STATUS_INVALID_PARAMETER        = 0xc000000d
	STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016
	STATUS_ACCESS_DENIED            = 0xc0000022
	STATUS_NO_SUCH_USER             = 0xc0000064
	STATUS_NOT_SUPPORTED            = 0xc00000bb
	STATUS_NETWORK_NAME_DELETED     = 0xc00000c9
	STATUS_NETWORK_ACCESS_DENIED    = 0xc00000ca
	STATUS_BAD_NETWORK_NAME         = 0xc00000cc
	STATUS_FILE_CLOSED              = 0xc0000128
	STATUS_USER_SESSION_DELETED     = 0xc0000203
	STATUS_NOT_FOUND                = 0xc0000225
)

type ErrorResponse struct {
	Response
}

func (er *ErrorResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(er.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2ErrorResponseStructureSize)
}

func (er *ErrorResponse) SetErrorData(data []byte) {
	binary.LittleEndian.PutUint32(er.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(data)))
	er.data = er.data[:SMB2HeaderSize+SMB2ErrorResponseMinSize]
	er.data = append(er.data, data...)
}

func NegotiateErrorResponse(status uint32) *ErrorResponse {
	er := &ErrorResponse{}
	er.data = make([]byte, SMB2HeaderSize+SMB2ErrorResponseMinSize)
	Header(er.data).SetStatus(status)
	Header(er.data).SetFlags(FLAGS_SERVER_TO_REDIR)
	return er
}

func (er *ErrorResponse) FromRequest(req GenericRequest) {
	er.Response.FromRequest(req)

	body := make([]byte, SMB2ErrorResponseMinSize)
	er.data = append(er.data, body...)
	Header(er.data).SetNextCommand(0)

	if Header(er.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(er.data).SetCreditResponse(0)
	} else {
		Header(er.data).SetCreditResponse(1)
	}

	er.setStructureSize()
}

func NewErrorResponse(req GenericRequest, status uint32, data []byte) *ErrorResponse {
	er := &ErrorResponse{}
	er.FromRequest(req)
	Header(er.data).SetStatus(status)
	er.SetErrorData(data)
	return er
}
