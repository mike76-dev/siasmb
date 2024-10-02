package smb

import "encoding/binary"

type Header struct {
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	ProcessID        uint32
	SecurityFeatures [8]byte
	TreeID           uint16
	UserID           uint16
	MuxID            uint16
}

func (h *Header) Decode(buf []byte) error {
	if len(buf) < 32 {
		return ErrWrongStructureLength
	}

	protocol := binary.LittleEndian.Uint32(buf[:4])
	if protocol != PROTOCOL_ID {
		return ErrWrongProtocol
	}

	h.Command = buf[4]
	h.Status = binary.LittleEndian.Uint32(buf[5:9])
	h.Flags = buf[9]
	h.Flags2 = binary.LittleEndian.Uint16(buf[10:12])

	ph := binary.LittleEndian.Uint16(buf[12:14])
	pl := binary.LittleEndian.Uint16(buf[26:28])
	h.ProcessID = (uint32(ph) << 16) | uint32(pl)

	copy(h.SecurityFeatures[:], buf[14:22])

	h.TreeID = binary.LittleEndian.Uint16(buf[24:26])
	h.UserID = binary.LittleEndian.Uint16(buf[28:30])
	h.MuxID = binary.LittleEndian.Uint16(buf[30:32])

	return nil
}

func (h *Header) Encode(buf []byte) error {
	if len(buf) < 32 {
		return ErrWrongStructureLength
	}

	binary.LittleEndian.PutUint32(buf[:4], PROTOCOL_ID)
	buf[4] = h.Command
	binary.LittleEndian.PutUint32(buf[5:9], h.Status)
	buf[9] = h.Flags
	binary.LittleEndian.PutUint16(buf[10:12], h.Flags2)
	binary.LittleEndian.PutUint16(buf[12:14], uint16(h.ProcessID>>16))

	copy(buf[14:22], h.SecurityFeatures[:])

	binary.LittleEndian.PutUint16(buf[24:26], h.TreeID)
	binary.LittleEndian.PutUint16(buf[26:28], uint16(h.ProcessID&0xffff))
	binary.LittleEndian.PutUint16(buf[28:30], h.UserID)
	binary.LittleEndian.PutUint16(buf[30:32], h.MuxID)

	return nil
}
