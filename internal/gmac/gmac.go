package gmac

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"hash"
)

type gmacHash struct {
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

// New returns a new AES-GMAC hash.
func New(signingKey, nonce []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(signingKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block) // 16-byte tag
	if err != nil {
		return nil, err
	}

	if len(nonce) != aead.NonceSize() { // must be 12 for GCM
		return nil, errors.New("invalid nonce")
	}

	n := make([]byte, len(nonce))
	copy(n, nonce)
	return &gmacHash{aead: aead, nonce: n}, nil
}

// Write implements hash.Hash.
func (g *gmacHash) Write(p []byte) (int, error) {
	g.buf = append(g.buf, p...)
	return len(p), nil
}

// Sum implements hash.Hash.
func (g *gmacHash) Sum(b []byte) []byte {
	// GMAC = GCM with empty plaintext, AAD = message.
	tag := g.aead.Seal(nil, g.nonce, nil, g.buf) // output is just tag
	return append(b, tag...)
}

// Reset implements hash.Hash.
func (g *gmacHash) Reset() { g.buf = g.buf[:0] }

// Size implements hash.Hash.
func (g *gmacHash) Size() int { return g.aead.Overhead() } // 16

// BlockSize implements hash.Hash.
func (g *gmacHash) BlockSize() int { return aes.BlockSize } // 16
