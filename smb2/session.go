package smb2

import (
	"encoding/binary"
)

const (
	SMB2SessionSetupRequestMinSize       = 24
	SMB2SessionSetupRequestStructureSize = 25

	SMB2SessionSetupResponseMinSize       = 8
	SMB2SessionSetupResponseStructureSize = 9
)

const (
	// Session flags.
	SESSION_FLAG_IS_GUEST = 0x0001
	SESSION_FLAG_IS_NULL  = 0x0002
)

// SessionSetupRequest represents an SMB2_SESSION_SETUP request.
type SessionSetupRequest struct {
	Request
}

// Validate implements GenericRequest interface.
func (ssr SessionSetupRequest) Validate() error {
	if err := Header(ssr.data).Validate(); err != nil {
		return err
	}

	if len(ssr.data) < SMB2HeaderSize+SMB2SessionSetupRequestMinSize {
		return ErrWrongLength
	}

	if ssr.structureSize() != SMB2SessionSetupRequestStructureSize {
		return ErrWrongFormat
	}

	return nil
}

// SecurityMode returns the SecurityMode field of the SMB2_SESSION_SETUP request.
func (ssr SessionSetupRequest) SecurityMode() uint16 {
	return uint16(ssr.data[SMB2HeaderSize+3])
}

// Capabilities returns the Capabilities field of the SMB2_SESSION_SETUP request.
func (ssr SessionSetupRequest) Capabilities() uint32 {
	return binary.LittleEndian.Uint32(ssr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

// PreviousSessionID returns the PreviousSessionID field of the SMB2_SESSION_SETUP request.
func (ssr SessionSetupRequest) PreviousSessionID() uint64 {
	return binary.LittleEndian.Uint64(ssr.data[SMB2HeaderSize+16 : SMB2HeaderSize+24])
}

// SecurityBuffer returns the Buffer field of the SMB2_SESSION_SETUP request.
func (ssr SessionSetupRequest) SecurityBuffer() []byte {
	off := binary.LittleEndian.Uint16(ssr.data[SMB2HeaderSize+12 : SMB2HeaderSize+14])
	length := binary.LittleEndian.Uint16(ssr.data[SMB2HeaderSize+14 : SMB2HeaderSize+16])
	if off+length > uint16(len(ssr.data)) {
		return nil
	}
	return ssr.data[off : off+length]
}

// SessionSetupResponse represents an SMB2_SESSION_SETUP response.
type SessionSetupResponse struct {
	Response
}

// setStructureSize sets the StructureSize field of the SMB2_SESSION_SETUP response.
func (ssr *SessionSetupResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(ssr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2SessionSetupResponseStructureSize)
}

// SetSessionFlags sets the SessionFlags field of the SMB2_SESSION_SETUP response.
func (ssr *SessionSetupResponse) SetSessionFlags(flags uint16) {
	binary.LittleEndian.PutUint16(ssr.data[SMB2HeaderSize+2:SMB2HeaderSize+4], flags)
}

// SetSecurityBuffer sets the Buffer field of the SMB2_SESSION_SETUP response.
func (ssr *SessionSetupResponse) SetSecurityBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(ssr.data[SMB2HeaderSize+4:SMB2HeaderSize+6], SMB2HeaderSize+SMB2SessionSetupResponseMinSize)
	binary.LittleEndian.PutUint16(ssr.data[SMB2HeaderSize+6:SMB2HeaderSize+8], uint16(len(buf)))
	ssr.data = ssr.data[:SMB2HeaderSize+SMB2SessionSetupResponseMinSize]
	ssr.data = append(ssr.data, buf...)
}

// FromRequest implements GenericResponse interface.
func (ssr *SessionSetupResponse) FromRequest(req GenericRequest) {
	ssr.Response.FromRequest(req)

	body := make([]byte, SMB2SessionSetupResponseMinSize)
	ssr.data = append(ssr.data, body...)

	ssr.setStructureSize()
	Header(ssr.data).SetNextCommand(0)
	if Header(ssr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(ssr.data).SetCreditResponse(0)
	} else {
		Header(ssr.data).SetCreditResponse(req.Header().CreditRequest())
	}
}

// Generate populates the fields of the SMB2_SESSION_SETUP response.
func (ssr *SessionSetupResponse) Generate(sid uint64, flags uint16, token []byte, done bool) {
	Header(ssr.data).SetSessionID(sid)
	Header(ssr.data).SetStatus(STATUS_OK)
	if !done { // Another step is required
		Header(ssr.data).SetStatus(STATUS_MORE_PROCESSING_REQUIRED)
	}

	ssr.SetSessionFlags(flags)
	ssr.SetSecurityBuffer(token)
}
