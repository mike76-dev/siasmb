package lznt1

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

var buf []byte
var out []byte

func TestCompress(t *testing.T) {
	sb, _ := rand.Int(rand.Reader, big.NewInt(2<<30))
	size := int(sb.Int64()) + 1
	buf = make([]byte, size)
	i := 0
	for i < size {
		m := 10000
		if i+m > size {
			m = size - i
		}
		cb, _ := rand.Int(rand.Reader, big.NewInt(int64(m)))
		c := int(cb.Int64() + 1)
		rand.Read(buf[i : i+c])
		i += c

		m = 10000
		if i+m > size {
			m = size - i
		}
		if m == 0 {
			break
		}
		cb, _ = rand.Int(rand.Reader, big.NewInt(int64(m)))
		c = int(cb.Int64() + 1)
		for j := 0; j < c; j++ {
			buf[i+j] = 0xff
		}
		i += c
	}

	out = Compress(buf)
	t.Logf("Input buffer: %d bytes; output buffer: %d bytes; deflation rate %.0f%%", len(buf), len(out), float32(len(buf)-len(out))/float32(len(buf))*100)
}

func TestDecompress(t *testing.T) {
	in, err := Decompress(out)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, in) {
		t.Error("output does not match input")
	}
}
