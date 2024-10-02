// Taken from https://github.com/hirochachacha/go-smb2
package ntlm

import (
	"bytes"
	"crypto/rc4"
	"errors"

	"github.com/mike76-dev/siasmb/utils"
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
	UserSID    string
	GroupSIDs  []string
	SessionKey []byte
}

func (s *Session) GetSecurityContext() (sc SecurityContext) {
	if s.user == "" {
		return
	}

	if s.domain == "" {
		return SecurityContext{
			UserSID:    "S-1-5-0-0",
			GroupSIDs:  []string{"S-1-5-0-544", "S-1-5-0-545"},
			SessionKey: s.exportedSessionKey,
		}
	}

	return SecurityContext{
		UserSID:    "S-1-5-0-0",
		GroupSIDs:  []string{"S-1-5-0-512", "S-1-5-0-513"},
		SessionKey: s.exportedSessionKey,
	}
}

func (s *Session) User() string {
	return s.user
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
