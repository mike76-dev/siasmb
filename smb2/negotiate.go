package smb2

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/utils"
)

const (
	SMBNegotiateRequestMinSize = 5 // Enough to validate a SMB_COM_NEGOTIATE request

	SMB2NegotiateRequestMinSize       = 36
	SMB2NegotiateRequestStructureSize = 36

	SMB2NegotiateResponseMinSize       = 64
	SMB2NegotiateResponseStructureSize = 65
)

const (
	MaxTransactSize = 1048576 * 4 // 4MiB
	MaxReadSize     = 1048576 * 4 // 4MiB
	MaxWriteSize    = 1048576 * 4 // 4MiB
)

const (
	// SMB dialects.
	SMB_DIALECT_1     = "NT LM 0.12"
	SMB_DIALECT_2     = "SMB 2.002"
	SMB_DIALECT_MULTI = "SMB 2.???"

	// SMB2 dialects.
	SMB_DIALECT_202         = 0x0202
	SMB_DIALECT_21          = 0x0210
	SMB_DIALECT_30          = 0x0300
	SMB_DIALECT_302         = 0x0302
	SMB_DIALECT_311         = 0x0311
	SMB_DIALECT_MULTICREDIT = 0x02ff
	SMB_DIALECT_UNKNOWN     = 0xffff
)

const (
	// MinSupportedDialect is the minimum dialect that is supported by the server.
	MinSupportedDialect = SMB_DIALECT_202

	// MaxSupportedDialect is the maximum dialect that is supported by the server.
	MaxSupportedDialect = SMB_DIALECT_21
)

const (
	// Security modes.
	NEGOTIATE_SIGNING_ENABLED  = 0x0001
	NEGOTIATE_SIGNING_REQUIRED = 0x0002
)

const (
	// Capabilities.
	GLOBAL_CAP_DFS                = 0x00000001
	GLOBAL_CAP_LEASING            = 0x00000002
	GLOBAL_CAP_LARGE_MTU          = 0x00000004
	GLOBAL_CAP_MULTI_CHANNEL      = 0x00000008
	GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
	GLOBAL_CAP_DIRECTORY_LEASING  = 0x00000020
	GLOBAL_CAP_ENCRYPTION         = 0x00000040
	GLOBAL_CAP_NOTIFICATIONS      = 0x00000080
)

var (
	ErrDialectNotSupported = errors.New("dialect not supported")
	ErrInvalidParameter    = errors.New("wrong parameter supplied")
)

// NegotiateRequest represents an SMB2_NEGOTIATE request.
type NegotiateRequest struct {
	Request
}

// Validate implements GenericRequest interface.
func (nr NegotiateRequest) Validate() error {
	if err := Header(nr.data).Validate(); err != nil {
		return err
	}

	if Header(nr.data).IsSmb() { // SMB_COM_NEGOTIATE
		if len(nr.data) < SMBHeaderSize+SMBNegotiateRequestMinSize {
			return ErrWrongLength
		}

		if nr.data[SMBHeaderSize] != 0 {
			return ErrWrongFormat
		}

		if binary.LittleEndian.Uint16(nr.data[SMBHeaderSize+1:SMBHeaderSize+3]) < 2 {
			return ErrWrongFormat
		}

		dialects := utils.NullTerminatedToStrings(nr.data[SMBHeaderSize+4:])
		if len(dialects) == 0 {
			return ErrInvalidParameter
		}

		var supported bool
		for _, d := range dialects {
			switch d {
			case SMB_DIALECT_2:
				supported = true
			case SMB_DIALECT_MULTI:
				if MaxSupportedDialect != SMB_DIALECT_202 {
					supported = true
				}
			}
			if supported {
				break
			}
		}

		if !supported {
			return ErrDialectNotSupported
		}

		return nil
	}

	if len(nr.data) < SMB2HeaderSize+SMB2NegotiateRequestMinSize {
		return ErrWrongLength
	}

	if nr.structureSize() != SMB2NegotiateRequestStructureSize {
		return ErrWrongFormat
	}

	if Header(nr.data).IsFlagSet(FLAGS_SIGNED) {
		return ErrInvalidParameter
	}

	dialectCount := binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
	if dialectCount == 0 {
		return ErrInvalidParameter
	}

	if len(nr.data) < SMB2HeaderSize+SMB2NegotiateRequestMinSize+2*int(dialectCount) {
		return ErrWrongLength
	}

	var supported bool
	for i := 0; i < int(dialectCount); i++ {
		dialect := binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+SMB2NegotiateRequestMinSize+i*2 : SMB2HeaderSize+SMB2NegotiateRequestMinSize+i*2+2])
		if dialect >= MinSupportedDialect && dialect <= MaxSupportedDialect {
			supported = true
			break
		}
	}

	if !supported {
		return ErrDialectNotSupported
	}

	return nil
}

// SecurityMode returns the SecurityMode field of the SMB2_NEGOTIATE request.
func (nr NegotiateRequest) SecurityMode() uint16 {
	return binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+4 : SMB2HeaderSize+6])
}

// Capabilities returns the Capabilities field of the SMB2_NEGOTIATE request.
func (nr NegotiateRequest) Capabilities() uint32 {
	return binary.LittleEndian.Uint32(nr.data[SMB2HeaderSize+8 : SMB2HeaderSize+12])
}

// ClientGuid returns the ClientGuid field of the SMB2_NEGOTIATE request.
func (nr NegotiateRequest) ClientGuid() []byte {
	guid := make([]byte, 16)
	copy(guid, nr.data[SMB2HeaderSize+12:SMB2HeaderSize+28])
	return guid
}

// MaxCommonDialect returns the greatest dialect supported both by the client and the server.
func (nr NegotiateRequest) MaxCommonDialect() uint16 {
	var max uint16
	if Header(nr.data).IsSmb() { // SMB_COM_NEGOTIATE
		dialects := utils.NullTerminatedToStrings(nr.data[SMBHeaderSize+4:])
		for _, d := range dialects {
			switch d {
			case SMB_DIALECT_2:
				if max < SMB_DIALECT_202 && MinSupportedDialect <= SMB_DIALECT_202 {
					max = SMB_DIALECT_202
				}
			case SMB_DIALECT_MULTI:
				if max < SMB_DIALECT_MULTICREDIT && MaxSupportedDialect >= SMB_DIALECT_202 {
					max = SMB_DIALECT_MULTICREDIT
				}
			}
		}
	} else {
		dialectCount := binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
		for i := 0; i < int(dialectCount); i++ {
			dialect := binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+SMB2NegotiateRequestMinSize+i*2 : SMB2HeaderSize+SMB2NegotiateRequestMinSize+i*2+2])
			if dialect > max && dialect >= MinSupportedDialect && dialect <= MaxSupportedDialect {
				max = dialect
			}
		}
	}

	return max
}

// NegotiateResponse represents an SMB2_NEGOTIATE response.
type NegotiateResponse struct {
	Response
}

// setStructureSize sets the StructureSize field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2NegotiateResponseStructureSize)
}

// SetSecurityMode sets the SecurityMode field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetSecurityMode(sm uint16) {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+2:SMB2HeaderSize+4], sm)
}

// SetDialectRevision sets the DialectRevision field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetDialectRevision(dialect uint16) {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+4:SMB2HeaderSize+6], dialect)
}

// SetServerGuid sets the ServerGuid field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetServerGuid(guid []byte) {
	copy(nr.data[SMB2HeaderSize+8:SMB2HeaderSize+24], guid)
}

// SetCapabilities sets the Capabilities field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetCapabilities(cap uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+24:SMB2HeaderSize+28], cap)
}

// SetMaxTransactSize sets the MaxTransactSize field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetMaxTransactSize(size uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+28:SMB2HeaderSize+32], size)
}

// SetMaxReadSize sets the MaxReadSize field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetMaxReadSize(size uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+32:SMB2HeaderSize+36], size)
}

// SetMaxWriteSize sets the M<axWriteSize field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetMaxWriteSize(size uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+36:SMB2HeaderSize+40], size)
}

// SetSystemTime sets the SystemTime field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetSystemTime(t time.Time) {
	binary.LittleEndian.PutUint64(nr.data[SMB2HeaderSize+40:SMB2HeaderSize+48], utils.UnixToFiletime(t))
}

// SetSecurityBuffer sets the Buffer field of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) SetSecurityBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+56:SMB2HeaderSize+58], SMB2HeaderSize+SMB2NegotiateResponseMinSize)
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+58:SMB2HeaderSize+60], uint16(len(buf)))
	nr.data = nr.data[:SMB2HeaderSize+SMB2NegotiateResponseMinSize]
	nr.data = append(nr.data, buf...)
}

// NewNegotiateResponse generates an SMB2_NEGOTIATE response to an SMB_COM_NEGOTIATE request.
func NewNegotiateResponse(serverGuid []byte, ns *ntlm.Server, dialect uint16) *NegotiateResponse {
	nr := &NegotiateResponse{}
	nr.data = make([]byte, SMB2HeaderSize+SMB2NegotiateResponseMinSize)
	h := NewHeader(nr.data)
	h.SetCommand(SMB2_NEGOTIATE)
	h.SetStatus(STATUS_OK)
	h.SetFlags(FLAGS_SERVER_TO_REDIR)
	nr.Generate(serverGuid, ns, dialect)
	return nr
}

// FromRequest implements GenericResponse interface.
func (nr *NegotiateResponse) FromRequest(req GenericRequest) {
	nr.Response.FromRequest(req)

	body := make([]byte, SMB2NegotiateResponseMinSize)
	nr.data = append(nr.data, body...)
	Header(nr.data).SetNextCommand(0)

	r, ok := req.(NegotiateRequest)
	if !ok {
		panic("not a negotiate request")
	}

	if NegotiateRequest(r).SecurityMode()&NEGOTIATE_SIGNING_REQUIRED > 0 {
		nr.SetSecurityMode(r.SecurityMode() | NEGOTIATE_SIGNING_REQUIRED)
	}
}

// Generate populates the fields of the SMB2_NEGOTIATE response.
func (nr *NegotiateResponse) Generate(serverGuid []byte, ns *ntlm.Server, dialect uint16) {
	token, err := ns.Negotiate()
	if err != nil {
		panic(err)
	}

	if Header(nr.data).IsFlagSet(FLAGS_ASYNC_COMMAND) {
		Header(nr.data).SetCreditResponse(0)
	} else {
		Header(nr.data).SetCreditResponse(1)
	}

	nr.setStructureSize()
	nr.SetDialectRevision(dialect)
	nr.SetSecurityMode(NEGOTIATE_SIGNING_ENABLED)
	nr.SetCapabilities(GLOBAL_CAP_DFS | GLOBAL_CAP_LARGE_MTU)
	nr.SetServerGuid(serverGuid)
	nr.SetMaxTransactSize(MaxTransactSize)
	nr.SetMaxReadSize(MaxReadSize)
	nr.SetMaxWriteSize(MaxWriteSize)
	nr.SetSystemTime(time.Now())

	nr.SetSecurityBuffer(token)
}
