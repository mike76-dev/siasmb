package utils

import (
	"time"
)

const filetimeOffset = 11644473600

func UnixToFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+filetimeOffset) * 1e7
}

func FiletimeToUnix(ft uint64) time.Time {
	return time.Unix(int64(ft)/1e7-filetimeOffset, 0)
}
