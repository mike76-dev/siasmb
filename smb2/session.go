package smb2

import (
	"encoding/binary"

	"github.com/mike76-dev/siasmb/smb"
)

const SMB2_SESSION_FLAG_BINDING = 0x01

type SessionSetupRequest struct {
	Header            Header
	Flags             uint8
	SecurityMode      uint8
	Capabilities      uint32
	Channel           uint32
	PreviousSessionID uint64
	SecurityBuffer    []byte
}

func (ssr *SessionSetupRequest) Decode(buf []byte) error {
	if len(buf) < 24 {
		return smb.ErrWrongDataLength
	}

	if binary.LittleEndian.Uint16(buf[:2]) != 25 {
		return smb.ErrWrongStructureLength
	}

	ssr.Flags = buf[2]
	ssr.SecurityMode = buf[3]
	ssr.Capabilities = binary.LittleEndian.Uint32(buf[4:8])
	ssr.Channel = binary.LittleEndian.Uint32(buf[8:12])
	ssr.PreviousSessionID = binary.LittleEndian.Uint64(buf[16:24])

	offset := binary.LittleEndian.Uint16((buf[12:14])) - 64
	length := binary.LittleEndian.Uint16(buf[14:16])
	if length > 0 {
		ssr.SecurityBuffer = make([]byte, length)
		copy(ssr.SecurityBuffer, buf[offset:])
	}

	return nil
}

type SessionSetupResponse struct {
	Header         Header
	SessionFlags   uint16
	SecurityBuffer []byte
}

func (ssr *SessionSetupResponse) Encode(buf []byte) error {
	if len(buf) < 64+8+len(ssr.SecurityBuffer) {
		return smb.ErrWrongDataLength
	}

	if err := ssr.Header.Encode(buf); err != nil {
		return err
	}

	binary.LittleEndian.PutUint16(buf[64:66], 9)
	binary.LittleEndian.PutUint16(buf[66:68], ssr.SessionFlags)
	if ssr.SecurityBuffer != nil {
		binary.LittleEndian.PutUint16(buf[68:70], 64+8)
		binary.LittleEndian.PutUint16(buf[70:72], uint16(len(ssr.SecurityBuffer)))
		copy(buf[72:], ssr.SecurityBuffer)
	}

	return nil
}

func (ssr *SessionSetupResponse) EncodedLength() int {
	return 64 + 8 + len(ssr.SecurityBuffer)
}

func (ssr *SessionSetupResponse) GetHeader() Header {
	return ssr.Header
}

func (req *Request) NewSessionSetupResponse(sid uint64) *SessionSetupResponse {
	ssr := &SessionSetupResponse{
		Header:       *req.Header,
		SessionFlags: SMB2_SESSION_FLAG_IS_GUEST,
	}

	ssr.Header.Status = SMB2_STATUS_OK
	ssr.Header.NextCommand = 0
	ssr.Header.Flags |= SMB2_FLAGS_SERVER_TO_REDIR
	ssr.Header.Credits = 1
	ssr.Header.SessionID = sid

	if req.AsyncID > 0 {
		ssr.Header.AsyncID = req.AsyncID
		ssr.Header.Flags |= SMB2_FLAGS_ASYNC_COMMAND
		ssr.Header.Credits = 0
	}

	return ssr
}
