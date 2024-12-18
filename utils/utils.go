package utils

import (
	"math"
	"strings"
)

// Roundup calculates the upper bound of a number alighed to the specified byte number.
func Roundup(x, bound int) int {
	return (x + (bound - 1)) &^ (bound - 1)
}

// ExtractFilename extracts the name of the file from a renterd object path.
func ExtractFilename(path string) (filepath string, filename string, isDir bool) {
	if path == "" || path == "/" {
		return "", "", true
	}

	filepath = path[1:]
	if path[len(path)-1] == '/' {
		isDir = true
		filepath = filepath[:len(filepath)-1]
	}

	i := strings.LastIndex(filepath, "/")
	if i < 0 {
		filename = filepath
	} else {
		filename = filepath[i+1:]
	}

	return
}

// FindMinKey finds a key-value pair with the smallest key in the map.
func FindMinKey[T any](m map[uint64]T) (key uint64, value T) {
	key = math.MaxUint64
	for k, v := range m {
		if k < key {
			key = k
			value = v
		}
	}
	return
}

// FindMaxKey finds a key-value pair with the greatest key in the map.
func FindMaxKey[T any](m map[uint64]T) (key uint64, value T) {
	for k, v := range m {
		if k > key {
			key = k
			value = v
		}
	}
	return
}
