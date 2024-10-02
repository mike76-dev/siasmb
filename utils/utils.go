package utils

import (
	"time"
	"unicode/utf16"
)

const filetimeOffset = 11644473600

func UnixToFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+filetimeOffset) * 1e7
}

func FiletimeToUnix(ft uint64) time.Time {
	return time.Unix(int64(ft)/1e7-filetimeOffset, 0)
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

func StringToUTF16LE(s string) []byte {
	utf16Encoded := utf16.Encode([]rune(s))
	utf16Bytes := make([]byte, len(utf16Encoded)*2+2)
	for i, r := range utf16Encoded {
		utf16Bytes[i*2] = byte(r)
		utf16Bytes[i*2+1] = byte(r >> 8)
	}

	return utf16Bytes
}

func Roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}
