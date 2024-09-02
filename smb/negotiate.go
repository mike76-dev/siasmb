package smb

import (
	"encoding/binary"

	"github.com/mike76-dev/siasmb/utils"
)

type NegotiateRequest []byte

func (nr NegotiateRequest) Decode() ([]string, error) {
	if len(nr) < 5 {
		return nil, ErrWrongDataLength
	}

	if nr[0] != 0 {
		return nil, ErrWrongParameters
	}

	length := binary.LittleEndian.Uint16(nr[1:3])
	if length < 2 {
		return nil, ErrWrongDataLength
	}

	if nr[3] != 2 {
		return nil, ErrWrongArgument
	}

	return utils.NullTerminatedToStrings(nr[4:]), nil
}
