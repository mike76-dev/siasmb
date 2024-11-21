// Taken from https://github.com/hirochachacha/go-smb2
package ntlm

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"errors"

	"github.com/mike76-dev/siasmb/utils"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"golang.org/x/crypto/blake2b"
)

type Session struct {
	isClientSide bool

	user   string
	domain string

	negotiateFlags     uint32
	exportedSessionKey []byte
	clientSigningKey   []byte
	serverSigningKey   []byte

	clientHandle *rc4.Cipher
	serverHandle *rc4.Cipher

	infoMap map[uint16][]byte
}

type SecurityContext struct {
	User       string
	Domain     string
	UserRID    uint32
	DomainSID  *dtyp.SID
	SessionKey []byte
}

func (s *Session) GetSecurityContext() (sc SecurityContext) {
	if s.user == "" {
		return
	}

	h, _ := blake2b.New256(nil)
	h.Write([]byte(s.user))
	if s.domain == "" {
		hash := h.Sum(nil)
		return SecurityContext{
			User:    s.user,
			UserRID: binary.LittleEndian.Uint32(hash[:4]),
			DomainSID: &dtyp.SID{
				Revision:          1,
				SubAuthorityCount: 2,
				IDAuthority: &dtyp.SIDIDAuthority{
					Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				},
				SubAuthority: []uint32{0, 0},
			},
			SessionKey: s.exportedSessionKey,
		}
	}

	h.Write([]byte(s.domain))
	hash := h.Sum(nil)
	return SecurityContext{
		User:    s.user,
		Domain:  s.domain,
		UserRID: binary.LittleEndian.Uint32(hash[:4]),
		DomainSID: &dtyp.SID{
			Revision:          1,
			SubAuthorityCount: 4,
			IDAuthority: &dtyp.SIDIDAuthority{
				Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
			},
			SubAuthority: []uint32{
				0x15,
				binary.LittleEndian.Uint32(hash[4:8]),
				binary.LittleEndian.Uint32(hash[8:12]),
				binary.LittleEndian.Uint32(hash[12:16]),
			},
		},
		SessionKey: s.exportedSessionKey,
	}
}

func (s *Session) User() string {
	return s.user
}

func (s *Session) Domain() string {
	return s.domain
}

func (s *Session) SessionKey() []byte {
	return s.exportedSessionKey
}

type InfoMap struct {
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
	// Flags           uint32
	// Timestamp       time.Time
	// SingleHost
	// TargetName string
	// ChannelBindings
}

func (s *Session) InfoMap() *InfoMap {
	return &InfoMap{
		NbComputerName:  utils.DecodeToString(s.infoMap[MsvAvNbComputerName]),
		NbDomainName:    utils.DecodeToString(s.infoMap[MsvAvNbDomainName]),
		DnsComputerName: utils.DecodeToString(s.infoMap[MsvAvDnsComputerName]),
		DnsDomainName:   utils.DecodeToString(s.infoMap[MsvAvDnsDomainName]),
		DnsTreeName:     utils.DecodeToString(s.infoMap[MsvAvDnsTreeName]),
		// Flags:        binary.LittleEndian.Uint32(s.infoMap[MsvAvFlags]),
	}
}

func (s *Session) Overhead() int {
	return 16
}

func (s *Session) Sum(plaintext []byte, seqNum uint32) ([]byte, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		return nil, 0
	}

	if s.isClientSide {
		return mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	}
	return mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
}

func (s *Session) CheckSum(sum, plaintext []byte, seqNum uint32) (bool, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		if sum == nil {
			return true, 0
		}
		return false, 0
	}

	if s.isClientSide {
		ret, seqNum := mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		if !bytes.Equal(sum, ret) {
			return false, 0
		}
		return true, seqNum
	}
	ret, seqNum := mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	if !bytes.Equal(sum, ret) {
		return false, 0
	}
	return true, seqNum
}

func (s *Session) Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32) {
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+16)

	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.clientHandle.XORKeyStream(ciphertext[16:], plaintext)

		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(ciphertext[16:], plaintext)

		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	}

	return ret, seqNum
}

func (s *Session) Unseal(dst, ciphertext []byte, seqNum uint32) ([]byte, uint32, error) {
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-16)

	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.serverHandle.XORKeyStream(plaintext, ciphertext[16:])

		var sum []byte

		if s.isClientSide {
			sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(plaintext, ciphertext[16:])

		var sum []byte

		if s.isClientSide {
			sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	default:
		copy(plaintext, ciphertext[16:])
		for _, s := range ciphertext[:16] {
			if s != 0x0 {
				return nil, 0, errors.New("signature mismatch")
			}
		}
	}

	return ret, seqNum, nil
}
