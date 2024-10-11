package smb2

import (
	"encoding/binary"
)

const (
	SMB2LogoffRequestMinSize       = 4
	SMB2LogoffRequestStructureSize = 4

	SMB2LogoffResponseMinSize       = 4
	SMB2LogoffResponseStructureSize = 4
)

type LogoffRequest struct {
	Request
}

func (lr LogoffRequest) Validate() error {
	if err := Header(lr.data).Validate(); err != nil {
		return err
	}

	if len(lr.data) < SMB2HeaderSize+SMB2LogoffRequestMinSize {
		return ErrWrongLength
	}

	if lr.structureSize() != SMB2LogoffRequestStructureSize {
		return ErrWrongFormat
	}

	return nil
}

type LogoffResponse struct {
	Response
}

func (lr *LogoffResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(lr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2LogoffResponseStructureSize)
}

func (lr *LogoffResponse) FromRequest(req GenericRequest) {
	lr.Response.FromRequest(req)

	body := make([]byte, SMB2LogoffResponseMinSize)
	lr.data = append(lr.data, body...)

	lr.setStructureSize()
	Header(lr.data).SetNextCommand(0)
	Header(lr.data).SetStatus(STATUS_OK)
	if Header(lr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(lr.data).SetCreditResponse(0)
	} else {
		Header(lr.data).SetCreditResponse(1)
	}
}
