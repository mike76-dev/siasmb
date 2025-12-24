package smb2

import "encoding/binary"

const (
	SMB2FlushRequestMinSize       = 24
	SMB2FlushRequestStructureSize = 24

	SMB2FlushResponseMinSize       = 4
	SMB2FlushResponseStructureSize = 4
)

// FlushRequest represents an SMB2_FLUSH request.
type FlushRequest struct {
	Request
}

// Validate implements GenericRequest interface.
func (fr FlushRequest) Validate(_ bool) error {
	if err := Header(fr.data).Validate(); err != nil {
		return err
	}

	if len(fr.data) < SMB2HeaderSize+SMB2FlushRequestMinSize {
		return ErrWrongLength
	}

	if fr.structureSize() != SMB2FlushRequestStructureSize {
		return ErrWrongFormat
	}

	return nil
}

// FileID returns the FileID field of the SMB2_FLUSH request.
func (fr FlushRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, fr.data[SMB2HeaderSize+8:SMB2HeaderSize+24])
	return fid
}

// FlushResponse represents an SMB2_FLUSH response.
type FlushResponse struct {
	Response
}

// setStructureSize sets the StructureSize field of the SMB2_FLUSH response.
func (fr *FlushResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(fr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2FlushResponseStructureSize)
}

// FromRequest implements GenericResponse interface.
func (fr *FlushResponse) FromRequest(req GenericRequest) {
	fr.Response.FromRequest(req)

	body := make([]byte, SMB2FlushResponseMinSize)
	fr.data = append(fr.data, body...)

	fr.setStructureSize()
	Header(fr.data).SetNextCommand(0)
	Header(fr.data).SetStatus(STATUS_OK)
	if Header(fr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(fr.data).SetCreditResponse(0)
	}
}
