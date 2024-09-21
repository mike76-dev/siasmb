package smb2

import (
	"encoding/binary"

	"github.com/mike76-dev/siasmb/smb"
)

type ErrorResponse struct {
	Header            Header
	ErrorContextCount uint8
	ErrorData         []byte
}

func (er *ErrorResponse) Encode(buf []byte) error {
	if len(buf) < 64+8+len(er.ErrorData) {
		return smb.ErrWrongDataLength
	}

	if err := er.Header.Encode(buf); err != nil {
		return err
	}

	binary.LittleEndian.PutUint16(buf[64:66], 9)
	buf[66] = er.ErrorContextCount
	binary.LittleEndian.PutUint32(buf[68:72], uint32(len(er.ErrorData)))
	if len(er.ErrorData) > 0 {
		copy(buf[72:], er.ErrorData)
	}

	return nil
}

func (er *ErrorResponse) EncodedLength() int {
	return 64 + 8 + len(er.ErrorData)
}

func (er *ErrorResponse) GetHeader() Header {
	return er.Header
}

func (req *Request) NewErrorResponse(status uint32, ecc uint8, data []byte) *ErrorResponse {
	er := &ErrorResponse{
		Header:            *req.Header,
		ErrorContextCount: ecc,
		ErrorData:         data,
	}
	er.Header.Status = status
	er.Header.NextCommand = 0
	er.Header.Flags |= SMB2_FLAGS_SERVER_TO_REDIR
	if req.AsyncID > 0 {
		er.Header.AsyncID = req.AsyncID
		er.Header.Flags |= SMB2_FLAGS_ASYNC_COMMAND
		er.Header.Credits = 0
	} else {
		er.Header.Credits = 1
	}
	return er
}
