package utils

import (
	"encoding/binary"
	"unicode/utf16"
)

// EncodedStringLen returns the length of an UTF-16-encoded string in bytes.
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

// EncodeString encodes a string in the UTF-16LE format.
func EncodeString(dst []byte, src string) int {
	ws := utf16.Encode([]rune(src))
	for i, w := range ws {
		binary.LittleEndian.PutUint16(dst[2*i:2*i+2], w)
	}
	return len(ws) * 2
}

// EncodeStringToBytes encodes a string in the UTF-16LE format; the result is returned.
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

// DecodeToString decodes an UTF-16LE-encoded string.
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

// NullTerminatedToStrings converts a sequence of null-terminated Unicode strings to a slice of Golang strings.
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
