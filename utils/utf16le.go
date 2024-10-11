package utils

import (
	"encoding/binary"
	"unicode/utf16"
)

func EncodedStringLen(s string) int {
	l := 0
	for _, r := range s {
		if 0x10000 <= r && r <= '\U0010FFFF' {
			l += 4
		} else {
			l += 2
		}
	}
	return l
}

func EncodeString(dst []byte, src string) int {
	ws := utf16.Encode([]rune(src))
	for i, w := range ws {
		binary.LittleEndian.PutUint16(dst[2*i:2*i+2], w)
	}
	return len(ws) * 2
}

func EncodeStringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	ws := utf16.Encode([]rune(s))
	bs := make([]byte, len(ws)*2)
	for i, w := range ws {
		binary.LittleEndian.PutUint16(bs[2*i:2*i+2], w)
	}
	return bs
}

func DecodeToString(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}
	ws := make([]uint16, len(bs)/2)
	for i := range ws {
		ws[i] = binary.LittleEndian.Uint16(bs[2*i : 2*i+2])
	}
	if len(ws) > 0 && ws[len(ws)-1] == 0 {
		ws = ws[:len(ws)-1]
	}
	return string(utf16.Decode(ws))
}

func NullTerminatedToStrings(b []byte) []string {
	var result []string
	for len(b) > 0 {
		if b[0] < 32 {
			if len(b) > 1 {
				b = b[1:]
			}
			continue
		}
		for i := 0; i < len(b); i++ {
			if b[i] == 0 {
				result = append(result, string(b[:i]))
				b = b[i+1:]
				break
			}
		}
	}
	if len(result) > 0 {
		return result
	}
	return []string{string(b)}
}
