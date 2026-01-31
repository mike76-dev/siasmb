package smb2

import "encoding/binary"

const (
	SMB2ReadRequestMinSize       = 48
	SMB2ReadRequestStructureSize = 49

	SMB2ReadResponseMinSize       = 16
	SMB2ReadResponseStructureSize = 17
)

const (
	// Read flags.
	READFLAG_READ_UNBUFFERED    = 0x01
	READFLAG_REQUEST_COMPRESSED = 0x02
)

// ReadRequest represents an SMB2_READ request.
type ReadRequest struct {
	Request
}

// Validate implements GenericRequest interface.
func (rr ReadRequest) Validate(supportsMultiCredit bool) error {
	if err := Header(rr.data).Validate(); err != nil {
		return err
	}

	if len(rr.data) < SMB2HeaderSize+SMB2ReadRequestMinSize {
		return ErrWrongLength
	}

	if rr.structureSize() != SMB2ReadRequestStructureSize {
		return ErrWrongFormat
	}

	// Validate CreditCharge.
	if supportsMultiCredit {
		sps := uint32(len(rr.data) - SMB2HeaderSize - SMB2ReadRequestMinSize)
		ers := rr.Length()
		if rr.Header().CreditCharge() == 0 {
			if sps > 65536 || ers > 65536 {
				return ErrInvalidParameter
			}
		} else if rr.Header().CreditCharge() < uint16((max(sps, ers)-1)/65536)+1 {
			return ErrInvalidParameter
		}
	}

	return nil
}

// Padding returns the Padding field of the SMB2_READ request.
func (rr ReadRequest) Padding() uint8 {
	return rr.data[SMB2HeaderSize+2]
}

// Flags returns the Flags field of the SMB2_READ request.
func (rr ReadRequest) Flags() uint8 {
	return rr.data[SMB2HeaderSize+3]
}

// Length returns the Length field of the SMB2_READ request.
func (rr ReadRequest) Length() uint32 {
	return binary.LittleEndian.Uint32(rr.data[SMB2HeaderSize+4 : SMB2HeaderSize+8])
}

// Offset returns the Offset field of the SMB2_READ request.
func (rr ReadRequest) Offset() uint64 {
	return binary.LittleEndian.Uint64(rr.data[SMB2HeaderSize+8 : SMB2HeaderSize+16])
}

// FileID returns the FileID field of the SMB2_READ request.
func (rr ReadRequest) FileID() []byte {
	fid := make([]byte, 16)
	copy(fid, rr.data[SMB2HeaderSize+16:SMB2HeaderSize+32])
	return fid
}

// MinimumCount returns the MinimumCount field of the SMB2_READ request.
func (rr ReadRequest) MinimumCount() uint32 {
	return binary.LittleEndian.Uint32(rr.data[SMB2HeaderSize+32 : SMB2HeaderSize+36])
}

// ReadResponse represents an SMB2_READ response.
type ReadResponse struct {
	Response
}

// setStructureSize sets the StructureSize field of the SMB2_READ response.
func (rr *ReadResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(rr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2ReadResponseStructureSize)
}

// SetData sets the Buffer field of the SMB2_READ response.
func (rr *ReadResponse) SetData(buf []byte, padding uint8) {
	if padding == 0 { // Edge case on Nautilus (Ubuntu)
		padding = SMB2HeaderSize + SMB2ReadResponseMinSize
	}
	if padding < SMB2HeaderSize+SMB2ReadResponseMinSize {
		return
	}
	rr.data[SMB2HeaderSize+2] = padding
	binary.LittleEndian.PutUint32(rr.data[SMB2HeaderSize+4:SMB2HeaderSize+8], uint32(len(buf)))
	add := make([]byte, padding-SMB2HeaderSize-SMB2ReadResponseMinSize)
	rr.data = append(rr.data, add...)
	rr.data = append(rr.data, buf...)
}

// FromRequest implements GenericResponse interface.
func (rr *ReadResponse) FromRequest(req GenericRequest) {
	rr.Response.FromRequest(req)

	body := make([]byte, SMB2ReadResponseMinSize)
	rr.data = append(rr.data, body...)

	rr.setStructureSize()
	Header(rr.data).SetNextCommand(0)
	Header(rr.data).SetStatus(STATUS_OK)
	if Header(rr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(rr.data).SetCreditResponse(0)
	} else {
		Header(rr.data).SetCreditResponse(max(req.Header().CreditCharge(), req.Header().CreditRequest()))
	}
}

// Generate populates the fields of the SMB2_READ response.
func (rr *ReadResponse) Generate(buf []byte, padding uint8) {
	rr.SetData(buf, padding)
}
