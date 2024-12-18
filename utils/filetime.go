package utils

import (
	"time"
)

// Unix time is represented in nanoseconds since January 1, 1970.
// Filetime is represented in 100-nanosecond intervals since January 1, 1601.
const filetimeOffset = 11644473600

// UnixToFiletime converts the Unix time to Filetime.
func UnixToFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+filetimeOffset) * 1e7
}

// FiletimeToUnix converts Filetime to the Unix time.
func FiletimeToUnix(ft uint64) time.Time {
	return time.Unix(int64(ft)/1e7-filetimeOffset, 0)
}
