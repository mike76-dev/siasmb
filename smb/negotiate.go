package smb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/mike76-dev/siasmb/utils"
)

type NegotiateRequest struct {
	Header   Header
	Dialects []string
}

func (nr *NegotiateRequest) Decode(buf []byte) error {
	if len(buf) < 5 {
		return ErrWrongDataLength
	}

	if buf[0] != 0 {
		return ErrWrongParameters
	}

	length := binary.LittleEndian.Uint16(buf[1:3])
	if length < 2 {
		return ErrWrongDataLength
	}

	if buf[3] != 2 {
		return ErrWrongArgument
	}

	nr.Dialects = utils.NullTerminatedToStrings(buf[4:])
	return nil
}

type NegotiateResponse struct {
	Header         Header
	Dialects       []string
	DialectIndex   uint16
	SecurityMode   uint8
	MaxMpxCount    uint16
	MaxNumberVcs   uint16
	MaxBufferSize  uint32
	MaxRawSize     uint32
	SessionKey     uint32
	Capabilities   uint32
	ServerTimeZone int16
	Challenge      []byte
	DomainName     string
}

func (nr *NegotiateResponse) Encode(buf []byte) error {
	wc := uint8(0x01)
	if nr.DialectIndex != 0xffff && nr.Dialects[nr.DialectIndex] == SMB_DIALECT_1 {
		wc = 0x11
	}

	if len(buf) < int(32+1+wc*2) {
		return ErrWrongStructureLength
	}

	if err := nr.Header.Encode(buf); err != nil {
		return fmt.Errorf("error encoding message header: %v", err)
	}

	buf[32] = wc
	binary.LittleEndian.PutUint16(buf[33:35], nr.DialectIndex)

	if nr.DialectIndex == 0xffff || nr.Dialects[nr.DialectIndex] != SMB_DIALECT_1 {
		binary.LittleEndian.PutUint16(buf[35:37], 0)
		return nil
	}

	buf[37] = nr.SecurityMode
	binary.LittleEndian.PutUint16(buf[38:40], nr.MaxMpxCount)
	binary.LittleEndian.PutUint16(buf[40:42], nr.MaxNumberVcs)
	binary.LittleEndian.PutUint32(buf[42:46], nr.MaxBufferSize)
	binary.LittleEndian.PutUint32(buf[46:50], nr.MaxRawSize)
	binary.LittleEndian.PutUint32(buf[50:54], nr.SessionKey)
	binary.LittleEndian.PutUint32(buf[54:58], nr.Capabilities)
	binary.LittleEndian.PutUint64(buf[58:66], utils.UnixToFiletime(time.Now()))

	_, tz := time.Now().Zone()
	binary.LittleEndian.PutUint16(buf[66:68], uint16(tz))

	buf[68] = byte(len(nr.Challenge))
	binary.LittleEndian.PutUint16(buf[69:71], uint16(len(nr.Challenge)+len(nr.DomainName)+1))

	if len(nr.Challenge) > 0 {
		copy(buf[71:71+len(nr.Challenge)], nr.Challenge)
	}

	copy(buf[71+len(nr.Challenge):71+len(nr.Challenge)+len(nr.DomainName)*2+2], utils.StringToUTF16LE(nr.DomainName))

	return nil
}

func (nr *NegotiateResponse) EncodedLength() int {
	if nr.DialectIndex == 0xffff || nr.Dialects[nr.DialectIndex] != SMB_DIALECT_1 {
		return 37
	}
	return 72 + len(nr.Challenge) + len(nr.DomainName)*2 + 2
}

func NewNegotiateResponse(h Header, dialects []string, dialect, domain string) NegotiateResponse {
	nr := NegotiateResponse{
		Header:   h,
		Dialects: dialects,
	}
	nr.Header.Status = SMB_STATUS_OK
	nr.Header.Flags = SMB_FLAGS_REPLY
	nr.Header.Flags2 = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE

	di := 0xffff
	for i, d := range dialects {
		if d == dialect {
			di = i
			break
		}
	}

	nr.DialectIndex = uint16(di)
	nr.SecurityMode = NEGOTIATE_SECURITY_SIGNATURES_ENABLED | NEGOTIATE_USER_SECURITY
	nr.MaxMpxCount = 1
	nr.MaxNumberVcs = 1
	nr.MaxBufferSize = 4356
	nr.MaxRawSize = 65535

	buf := make([]byte, 4)
	rand.Read(buf)
	nr.SessionKey = binary.LittleEndian.Uint32(buf)

	nr.Capabilities = CAP_NT_SMBS | CAP_STATUS32
	rand.Read(nr.Challenge)
	nr.DomainName = domain

	return nr
}

func (nr *NegotiateRequest) HasDialect(dialect string) bool {
	for _, d := range nr.Dialects {
		if d == dialect {
			return true
		}
	}
	return false
}
