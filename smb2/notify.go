package smb2

import "encoding/binary"

const (
	SMB2ChangeNotifyRequestMinSize       = 32
	SMB2ChangeNotifyRequestStructureSize = 32

	SMB2ChangeNotifyResponseMinSize       = 8
	SMB2ChangeNotifyResponseStructureSize = 9
)

const (
	// Notify flags.
	WATCH_TREE = 0x0001
)

const (
	// Completion filter flags.
	FILE_NOTIFY_CHANGE_FILE_NAME    = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME     = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES   = 0x00000004
	FILE_NOTIFY_CHANGE_SIZE         = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE   = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS  = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION     = 0x00000040
	FILE_NOTIFY_CHANGE_EA           = 0x00000080
	FILE_NOTIFY_CHANGE_SECURITY     = 0x00000100
	FILE_NOTIFY_CHANGE_STREAM_NAME  = 0x00000200
	FILE_NOTIFY_CHANGE_STREAM_SIZE  = 0x00000400
	FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800
)

// ChangeNotifyRequest represents an SMB2_CHANGE_NOTIFY request.
type ChangeNotifyRequest struct {
	Request
}

// Validate implements GenericRequest interface.
func (cnr ChangeNotifyRequest) Validate(supportsMultiCredit bool, _ uint16) error {
	if err := Header(cnr.data).Validate(); err != nil {
		return err
	}

	if len(cnr.data) < SMB2HeaderSize+SMB2ChangeNotifyRequestMinSize {
		return ErrWrongLength
	}

	if cnr.structureSize() != SMB2ChangeNotifyRequestStructureSize {
		return ErrWrongFormat
	}

	// Validate CreditCharge.
	if supportsMultiCredit {
		ers := cnr.OutputBufferLength()
		if cnr.Header().CreditCharge() == 0 {
			if ers > 65536 {
				return ErrInvalidParameter
			}
		} else if cnr.Header().CreditCharge() < uint16((ers-1)/65536)+1 {
			return ErrInvalidParameter
		}
	}

	return nil
}

// Flags returns the Flags field of the SMB2_CHANGE_NOTIFY request.
func (cnr ChangeNotifyRequest) Flags() uint16 {
	return binary.LittleEndian.Uint16(cnr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
}

// OutputBufferLength returns the OutBufferLength field of the SMB2_CHANGE_NOTIFY request.
func (cnr ChangeNotifyRequest) OutputBufferLength() uint32 {
	return binary.LittleEndian.Uint32(cnr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

// FileID returns the FileID field of the SMB2_CHANGE_NOTIFY request.
func (cnr ChangeNotifyRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, cnr.data[SMB2HeaderSize+8:SMB2HeaderSize+24])
	return fid
}

// CompletionFilter returns the CompletionFilter field of the SMB2_CHANGE_NOTIFY request.
func (cnr ChangeNotifyRequest) CompletionFilter() uint32 {
	return binary.LittleEndian.Uint32(cnr.data[SMB2HeaderSize+24 : SMB2HeaderSize+28])
}

// ChangeNotifyResponse represents an SMB2_CHANGE_NOTIFY response.
type ChangeNotifyResponse struct {
	Response
}

// setStructureSize sets the StructureSize field of the SMB2_CHANGE_NOTIFY response.
func (cnr *ChangeNotifyResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(cnr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2ChangeNotifyResponseStructureSize)
}

// SetOutputBuffer sets the Buffer field of the SMB2_CHANGE_NOTIFY response.
func (cnr *ChangeNotifyResponse) SetOutputBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(cnr.data[SMB2HeaderSize+2:SMB2HeaderSize+4], uint16(len(cnr.data)))
	binary.LittleEndian.PutUint32(cnr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(buf)))
	cnr.data = append(cnr.data, buf...)
}

// FromRequest implements GenericResponse interface.
func (cnr *ChangeNotifyResponse) FromRequest(req GenericRequest) {
	cnr.Response.FromRequest(req)

	body := make([]byte, SMB2ChangeNotifyResponseMinSize)
	cnr.data = append(cnr.data, body...)

	cnr.setStructureSize()
	Header(cnr.data).SetNextCommand(0)
	Header(cnr.data).SetStatus(STATUS_OK)
	if Header(cnr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(cnr.data).SetCreditResponse(0)
	} else {
		Header(cnr.data).SetCreditResponse(max(req.Header().CreditCharge(), req.Header().CreditRequest()))
	}
}

// Generate populates the fields of the SMB2_CHANGE_NOTIFY response.
func (cnr *ChangeNotifyResponse) Generate(buf []byte) {
	cnr.SetOutputBuffer(buf)
}
