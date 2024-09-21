package smb2

import (
	"encoding/binary"

	"github.com/mike76-dev/siasmb/smb"
)

type LogoffRequest struct {
	Header Header
}

func (lr *LogoffRequest) Decode(buf []byte) error {
	if len(buf) < 4 {
		return smb.ErrWrongDataLength
	}

	if binary.LittleEndian.Uint16(buf[:2]) != 4 {
		return smb.ErrWrongStructureLength
	}

	return nil
}

type LogoffResponse struct {
	Header Header
}

func (lr *LogoffResponse) Encode(buf []byte) error {
	if len(buf) < 64+4 {
		return smb.ErrWrongDataLength
	}

	if err := lr.Header.Encode(buf); err != nil {
		return err
	}

	binary.LittleEndian.PutUint16(buf[64:66], 4)
	return nil
}

func (lr *LogoffResponse) EncodedLength() int {
	return 64 + 4
}

func (lr *LogoffResponse) GetHeader() Header {
	return lr.Header
}

func (req *Request) NewLogoffResponse() *LogoffResponse {
	lr := &LogoffResponse{Header: *req.Header}

	lr.Header.Status = SMB2_STATUS_OK
	lr.Header.NextCommand = 0
	lr.Header.Flags |= SMB2_FLAGS_SERVER_TO_REDIR
	lr.Header.Credits = 1

	if req.AsyncID > 0 {
		lr.Header.AsyncID = req.AsyncID
		lr.Header.Flags |= SMB2_FLAGS_ASYNC_COMMAND
		lr.Header.Credits = 0
	}

	return lr
}
