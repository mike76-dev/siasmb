package smb2

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/utils"
)

const (
	SMBNegotiateRequestMinSize = 5

	SMB2NegotiateRequestMinSize       = 36
	SMB2NegotiateRequestStructureSize = 36

	SMB2NegotiateResponseMinSize       = 64
	SMB2NegotiateResponseStructureSize = 65
)

const (
	MaxTransactSize = 1048576 * 2
	MaxReadSize     = 1048576 * 2
	MaxWriteSize    = 1048576 * 2
)

const (
	SMB_DIALECT_1     = "NT LM 0.12"
	SMB_DIALECT_2     = "SMB 2.002"
	SMB_DIALECT_MULTI = "SMB 2.???"

	SMB_DIALECT_202         = 0x0202
	SMB_DIALECT_21          = 0x0210
	SMB_DIALECT_30          = 0x0300
	SMB_DIALECT_302         = 0x0302
	SMB_DIALECT_311         = 0x0311
	SMB_DIALECT_MULTICREDIT = 0x02ff
	SMB_DIALECT_UNKNOWN     = 0xffff
)

const (
	NEGOTIATE_SIGNING_ENABLED  = 0x0001
	NEGOTIATE_SIGNING_REQUIRED = 0x0002
)

const (
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
)

type NegotiateRequest struct {
	Request
}

func (nr *NegotiateRequest) Validate() error {
	if err := nr.header.Validate(); err != nil {
		return err
	}

	if nr.header.IsSmb() {
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
			return ErrWrongFormat
		}

		var supported bool
		for _, d := range dialects {
			if d == SMB_DIALECT_2 {
				supported = true
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

	dialectCount := binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+2 : SMB2HeaderSize+4])
	if dialectCount == 0 {
		return ErrWrongFormat
	}

	if len(nr.data) < SMB2HeaderSize+SMB2NegotiateRequestMinSize+2*int(dialectCount) {
		return ErrWrongLength
	}

	var supported bool
	for i := 0; i < int(dialectCount); i++ {
		dialect := binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+SMB2NegotiateRequestMinSize+i*2 : SMB2HeaderSize+SMB2NegotiateRequestMinSize+i*2+2])
		if dialect == SMB_DIALECT_202 {
			supported = true
			break
		}
	}

	if !supported {
		return ErrDialectNotSupported
	}

	return nil
}

func (nr *NegotiateRequest) SecurityMode() uint16 {
	return binary.LittleEndian.Uint16(nr.data[SMB2HeaderSize+4 : SMB2HeaderSize+6])
}

func (nr *NegotiateRequest) Capabilities() uint32 {
	return binary.LittleEndian.Uint32(nr.data[SMB2HeaderSize+8 : SMB2HeaderSize+12])
}

func (nr *NegotiateRequest) ClientGuid() []byte {
	guid := make([]byte, 16)
	copy(guid, nr.data[SMB2HeaderSize+12:SMB2HeaderSize+28])
	return guid
}

type NegotiateResponse struct {
	Response
}

func (nr *NegotiateResponse) setStructureSize() {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize:SMB2HeaderSize+2], SMB2NegotiateResponseStructureSize)
}

func (nr *NegotiateResponse) SetSecurityMode(sm uint16) {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+2:SMB2HeaderSize+4], sm)
}

func (nr *NegotiateResponse) SetDialectRevision(dialect uint16) {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+4:SMB2HeaderSize+6], dialect)
}

func (nr *NegotiateResponse) SetServerGuid(guid []byte) {
	copy(nr.data[SMB2HeaderSize+8:SMB2HeaderSize+24], guid)
}

func (nr *NegotiateResponse) SetCapabilities(cap uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+24:SMB2HeaderSize+28], cap)
}

func (nr *NegotiateResponse) SetMaxTransactSize(size uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+28:SMB2HeaderSize+32], size)
}

func (nr *NegotiateResponse) SetMaxReadSize(size uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+32:SMB2HeaderSize+36], size)
}

func (nr *NegotiateResponse) SetMaxWriteSize(size uint32) {
	binary.LittleEndian.PutUint32(nr.data[SMB2HeaderSize+36:SMB2HeaderSize+40], size)
}

func (nr *NegotiateResponse) SetSystemTime(t time.Time) {
	binary.LittleEndian.PutUint64(nr.data[SMB2HeaderSize+40:SMB2HeaderSize+48], utils.UnixToFiletime(t))
}

func (nr *NegotiateResponse) SetSecurityBuffer(buf []byte) {
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+56:SMB2HeaderSize+58], SMB2HeaderSize+SMB2NegotiateResponseMinSize)
	binary.LittleEndian.PutUint16(nr.data[SMB2HeaderSize+58:SMB2HeaderSize+60], uint16(len(buf)))
	nr.data = nr.data[:SMB2HeaderSize+SMB2NegotiateResponseMinSize]
	nr.data = append(nr.data, buf...)
}

func (nr *NegotiateResponse) New(serverGuid []byte, ns *ntlm.Server) {
	nr.data = make([]byte, SMB2HeaderSize)
	nr.header = GetHeader(nr.data)

	nr.header.SetCommand(SMB2_NEGOTIATE)
	nr.header.SetStatus(STATUS_OK)
	nr.header.SetFlags(FLAGS_SERVER_TO_REDIR)
}

func (nr *NegotiateResponse) Generate(serverGuid []byte, ns *ntlm.Server) {
	token, err := ns.Negotiate()
	if err != nil {
		panic(err)
	}

	body := make([]byte, SMB2NegotiateResponseMinSize)
	nr.data = append(nr.data, body...)

	if nr.header.IsFlagSet(FLAGS_ASYNC_COMMAND) {
		nr.header.SetCreditResponse(0)
	} else {
		nr.header.SetCreditResponse(1)
	}

	nr.setStructureSize()
	nr.SetDialectRevision(SMB_DIALECT_202)
	nr.SetSecurityMode(NEGOTIATE_SIGNING_ENABLED)
	nr.SetCapabilities(GLOBAL_CAP_DFS)
	nr.SetServerGuid(serverGuid)
	nr.SetMaxTransactSize(MaxTransactSize)
	nr.SetMaxReadSize(MaxReadSize)
	nr.SetMaxWriteSize(MaxWriteSize)

	nr.SetSecurityBuffer(token)
}
