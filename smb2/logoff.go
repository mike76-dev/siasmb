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

// LogoffRequest represents an SMB2_LOGOFF request.
type LogoffRequest struct {
	Request
}

// Validate implements GenericRequest interface.
func (lr LogoffRequest) Validate(_ bool, _ uint16) error {
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

// LogoffResponse represents an SMB2_LOGOFF response.
type LogoffResponse struct {
	Response
}

// setStructureSize sets the StructureSize field of the SMB2_LOGOFF response.
func (lr *LogoffResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(lr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2LogoffResponseStructureSize)
}

// FromRequest implements GenericResponse interface.
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
