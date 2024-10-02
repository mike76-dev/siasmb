package smb2

import (
	"encoding/binary"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/smb"
	"github.com/mike76-dev/siasmb/utils"
)

type NegotiateRequest struct {
	Header            Header
	SecurityMode      uint16
	Capabilities      uint32
	ClientGUID        [16]byte
	Dialects          []uint16
	NegotiateContexts []NegotiateContext
}

type NegotiateContext struct {
	ContextType uint16
	Data        []byte
}

func (nr *NegotiateRequest) Decode(buf []byte) error {
	if len(buf) < 36 {
		return smb.ErrWrongDataLength
	}

	if binary.LittleEndian.Uint16(buf[:2]) != 36 {
		return smb.ErrWrongStructureLength
	}

	dialectCount := binary.LittleEndian.Uint16(buf[2:4])
	if len(buf) < 36+2*int(dialectCount) {
		return smb.ErrWrongDataLength
	}

	nr.SecurityMode = binary.LittleEndian.Uint16(buf[4:6])
	nr.Capabilities = binary.LittleEndian.Uint32(buf[8:12])
	copy(nr.ClientGUID[:], buf[12:28])

	var is311 bool
	var nco uint32
	var ncc uint16
	for i := 0; i < int(dialectCount); i++ {
		dialect := binary.LittleEndian.Uint16(buf[36+i*2 : 38+i*2])
		nr.Dialects = append(nr.Dialects, dialect)
		if dialect == SMB_DIALECT_311 {
			is311 = true
			nco = binary.LittleEndian.Uint32(buf[28:32])
			ncc = binary.LittleEndian.Uint16(buf[32:34])
		}
	}

	if is311 {
		nco -= 64
		for ncc > 0 {
			var nc NegotiateContext
			nc.ContextType = binary.LittleEndian.Uint16(buf[nco : nco+2])
			length := binary.LittleEndian.Uint16(buf[nco+2 : nco+4])
			nc.Data = make([]byte, length)
			copy(nc.Data, buf[nco+8:nco+8+uint32(length)])
			nr.NegotiateContexts = append(nr.NegotiateContexts, nc)
			nco += uint32(utils.Roundup(8+int(length), 8))
			ncc--
		}
	}

	return nil
}

func (nr *NegotiateRequest) HasDialect(dialect uint16) bool {
	for _, d := range nr.Dialects {
		if d == dialect {
			return true
		}
	}
	return false
}

type NegotiateResponse struct {
	Header            Header
	SecurityMode      uint16
	DialectRevision   uint16
	ServerGUID        [16]byte
	Capabilities      uint32
	MaxTransactSize   uint32
	MaxReadSize       uint32
	MaxWriteSize      uint32
	SecurityBuffer    []byte
	NegotiateContexts []NegotiateContext
}

func (nr *NegotiateResponse) Encode(buf []byte) error {
	if len(buf) < 64+64+len(nr.SecurityBuffer) {
		return smb.ErrWrongDataLength
	}

	if err := nr.Header.Encode(buf); err != nil {
		return err
	}

	binary.LittleEndian.PutUint16(buf[64:66], 65)
	binary.LittleEndian.PutUint16(buf[66:68], nr.SecurityMode)
	binary.LittleEndian.PutUint16(buf[68:70], nr.DialectRevision)
	copy(buf[72:88], nr.ServerGUID[:])
	binary.LittleEndian.PutUint32(buf[88:92], nr.Capabilities)
	binary.LittleEndian.PutUint32(buf[92:96], nr.MaxTransactSize)
	binary.LittleEndian.PutUint32(buf[96:100], nr.MaxReadSize)
	binary.LittleEndian.PutUint32(buf[100:104], nr.MaxWriteSize)
	binary.LittleEndian.PutUint64(buf[104:112], utils.UnixToFiletime(time.Now()))

	if len(nr.SecurityBuffer) > 0 {
		binary.LittleEndian.PutUint16(buf[120:122], 128)
		binary.LittleEndian.PutUint16(buf[122:124], uint16(len(nr.SecurityBuffer)))
	}

	if len(nr.SecurityBuffer) > 0 {
		copy(buf[128:128+len(nr.SecurityBuffer)], nr.SecurityBuffer)
	}

	if nr.DialectRevision == SMB_DIALECT_311 {
		binary.LittleEndian.PutUint16(buf[70:72], uint16(len(nr.NegotiateContexts)))
		nco := uint32(utils.Roundup(128+len(nr.SecurityBuffer), 8))
		binary.LittleEndian.PutUint32(buf[124:128], nco)
		for _, nc := range nr.NegotiateContexts {
			binary.LittleEndian.PutUint16(buf[nco:nco+2], nc.ContextType)
			binary.LittleEndian.PutUint16(buf[nco+2:nco+4], uint16(len(nc.Data)))
			copy(buf[nco+8:nco+8+uint32(len(nc.Data))], nc.Data)
			nco += uint32(utils.Roundup(8+len(nc.Data), 8))
		}
	}

	return nil
}

func (nr *NegotiateResponse) EncodedLength() int {
	res := 128
	if len(nr.NegotiateContexts) > 0 {
		res += utils.Roundup(len(nr.SecurityBuffer), 8)
	} else {
		res += len(nr.SecurityBuffer)
	}
	for i, nc := range nr.NegotiateContexts {
		if i < len(nr.NegotiateContexts)-1 {
			res += utils.Roundup(8+len(nc.Data), 8)
		} else {
			res += 8 + len(nc.Data)
		}
	}
	return res
}

func (nr *NegotiateResponse) GetHeader() Header {
	return nr.Header
}

func (req *Request) NewNegotiateResponse(serverGuid [16]byte, ns *ntlm.Server) *NegotiateResponse {
	nr := &NegotiateResponse{}
	if req.Header == nil {
		nr.Header.Command = SMB2_NEGOTIATE
	} else {
		nr.Header = *req.Header
	}

	nr.Header.Status = SMB2_STATUS_OK
	nr.Header.NextCommand = 0
	nr.Header.Flags |= SMB2_FLAGS_SERVER_TO_REDIR
	nr.Header.Credits = 1
	nr.DialectRevision = SMB_DIALECT_202
	nr.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	nr.Capabilities = SMB2_GLOBAL_CAP_DFS
	nr.ServerGUID = serverGuid
	nr.MaxTransactSize = MaxTransactSize
	nr.MaxReadSize = MaxReadSize
	nr.MaxWriteSize = MaxWriteSize

	if req.AsyncID > 0 {
		nr.Header.AsyncID = req.AsyncID
		nr.Header.Flags |= SMB2_FLAGS_ASYNC_COMMAND
		nr.Header.Credits = 0
	}

	token, err := ns.Negotiate()
	if err != nil {
		panic(err)
	}

	nr.SecurityBuffer = token

	return nr
}
