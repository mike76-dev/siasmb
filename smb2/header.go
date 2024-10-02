package smb2

import (
	"encoding/binary"
	"errors"

	"github.com/mike76-dev/siasmb/smb"
)

type Header struct {
	CreditCharge uint16
	Status       uint32
	Command      uint16
	Credits      uint16
	Flags        uint32
	NextCommand  uint32
	MessageID    uint64
	TreeID       uint32
	AsyncID      uint64
	SessionID    uint64
	Signature    [16]byte
}

func (h *Header) Decode(buf []byte) error {
	if len(buf) < 64 {
		return smb.ErrWrongDataLength
	}

	protocolID := binary.LittleEndian.Uint32(buf[:4])
	if protocolID != PROTOCOL_ID {
		return smb.ErrWrongProtocol
	}

	if binary.LittleEndian.Uint16(buf[4:6]) != 64 {
		return smb.ErrWrongStructureLength
	}

	h.CreditCharge = binary.LittleEndian.Uint16(buf[6:8])
	h.Status = binary.LittleEndian.Uint32(buf[8:12])
	h.Command = binary.LittleEndian.Uint16(buf[12:14])
	h.Credits = binary.LittleEndian.Uint16(buf[14:16])
	h.Flags = binary.LittleEndian.Uint32(buf[16:20])

	h.NextCommand = binary.LittleEndian.Uint32(buf[20:24])
	if h.NextCommand&7 != 0 {
		return errors.New("next command unaligned")
	}

	h.MessageID = binary.LittleEndian.Uint64(buf[24:32])
	h.SessionID = binary.LittleEndian.Uint64(buf[40:48])

	if h.Flags&SMB2_FLAGS_ASYNC_COMMAND > 0 {
		h.AsyncID = binary.LittleEndian.Uint64(buf[32:40])
	} else {
		h.TreeID = binary.LittleEndian.Uint32(buf[36:40])
	}

	copy(h.Signature[:], buf[48:64])

	return nil
}

func (h *Header) Encode(buf []byte) error {
	if len(buf) < 64 {
		return smb.ErrWrongDataLength
	}

	binary.LittleEndian.PutUint32(buf[:4], PROTOCOL_ID)
	binary.LittleEndian.PutUint16(buf[4:6], 64)
	binary.LittleEndian.PutUint16(buf[6:8], h.CreditCharge)
	binary.LittleEndian.PutUint32(buf[8:12], h.Status)
	binary.LittleEndian.PutUint16(buf[12:14], h.Command)
	binary.LittleEndian.PutUint16(buf[14:16], h.Credits)
	binary.LittleEndian.PutUint32(buf[16:20], h.Flags)
	binary.LittleEndian.PutUint32(buf[20:24], h.NextCommand)
	binary.LittleEndian.PutUint64(buf[24:32], h.MessageID)
	binary.LittleEndian.PutUint64(buf[40:48], h.SessionID)

	if h.Flags&SMB2_FLAGS_ASYNC_COMMAND > 0 {
		binary.LittleEndian.PutUint64(buf[32:40], h.AsyncID)
	} else {
		binary.LittleEndian.PutUint32(buf[36:40], h.TreeID)
	}

	copy(buf[48:64], h.Signature[:])

	return nil
}
