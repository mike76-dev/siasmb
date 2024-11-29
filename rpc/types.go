package rpc

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/utils"
	"github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	"github.com/oiweiwei/go-msrpc/ndr"
)

type Encoder interface {
	Encode(w io.Writer)
}

type Decoder interface {
	Decode(r io.Reader)
}

type SyntaxID struct {
	IfUUID         [16]byte
	IfVersionMajor uint16
	IfVersionMinor uint16
}

func (sid *SyntaxID) Encode(w io.Writer) {
	buf := make([]byte, 16)
	copy(buf, sid.IfUUID[:])
	buf = binary.LittleEndian.AppendUint16(buf, sid.IfVersionMajor)
	buf = binary.LittleEndian.AppendUint16(buf, sid.IfVersionMinor)
	w.Write(buf)
}

func (sid *SyntaxID) Decode(r io.Reader) {
	buf := make([]byte, 20)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	copy(sid.IfUUID[:], buf[:16])
	sid.IfVersionMajor = binary.LittleEndian.Uint16(buf[16:18])
	sid.IfVersionMinor = binary.LittleEndian.Uint16(buf[18:20])
}

type Context struct {
	ContextID        uint16
	AbstractSyntax   *SyntaxID
	TransferSyntaxes []*SyntaxID
}

func (c *Context) Encode(w io.Writer) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint16(buf, c.ContextID)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(c.TransferSyntaxes)))
	w.Write(buf)
	c.AbstractSyntax.Encode(w)
	for _, ts := range c.TransferSyntaxes {
		ts.Encode(w)
	}
}

func (c *Context) Decode(r io.Reader) {
	buf := make([]byte, 4)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	c.ContextID = binary.LittleEndian.Uint16(buf[:2])
	c.TransferSyntaxes = make([]*SyntaxID, binary.LittleEndian.Uint16(buf[2:]))
	c.AbstractSyntax = &SyntaxID{}
	c.AbstractSyntax.Decode(r)
	for i := range c.TransferSyntaxes {
		c.TransferSyntaxes[i] = &SyntaxID{}
		c.TransferSyntaxes[i].Decode(r)
	}
}

type Bind struct {
	MaxXmitFrag  uint16
	MaxRecvFrag  uint16
	AssocGroupID uint32
	ContextList  []*Context
}

func (b *Bind) Encode(w io.Writer) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint16(buf, b.MaxXmitFrag)
	buf = binary.LittleEndian.AppendUint16(buf, b.MaxRecvFrag)
	buf = binary.LittleEndian.AppendUint32(buf, b.AssocGroupID)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(b.ContextList)))
	w.Write(buf)
	for _, c := range b.ContextList {
		c.Encode(w)
	}
}

func (b *Bind) Decode(r io.Reader) {
	buf := make([]byte, 12)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	b.MaxXmitFrag = binary.LittleEndian.Uint16(buf[:2])
	b.MaxRecvFrag = binary.LittleEndian.Uint16(buf[2:4])
	b.AssocGroupID = binary.LittleEndian.Uint32(buf[4:8])
	b.ContextList = make([]*Context, binary.LittleEndian.Uint32(buf[8:]))
	for i := range b.ContextList {
		b.ContextList[i] = &Context{}
		b.ContextList[i].Decode(r)
	}
}

type Result struct {
	DefResult      uint16
	ProviderReason uint16
	TransferSyntax *SyntaxID
}

func (res *Result) Encode(w io.Writer) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint16(buf, res.DefResult)
	buf = binary.LittleEndian.AppendUint16(buf, res.ProviderReason)
	w.Write(buf)
	res.TransferSyntax.Encode(w)
}

func (res *Result) Decode(r io.Reader) {
	buf := make([]byte, 4)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	res.DefResult = binary.LittleEndian.Uint16(buf[:2])
	res.ProviderReason = binary.LittleEndian.Uint16(buf[2:4])
	res.TransferSyntax = &SyntaxID{}
	res.TransferSyntax.Decode(r)
}

type BindAck struct {
	MaxXmitFrag  uint16
	MaxRecvFrag  uint16
	AssocGroupID uint32
	PortSpec     string
	ResultList   []*Result
}

func (ba *BindAck) Encode(w io.Writer) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint16(buf, ba.MaxXmitFrag)
	buf = binary.LittleEndian.AppendUint16(buf, ba.MaxRecvFrag)
	buf = binary.LittleEndian.AppendUint32(buf, ba.AssocGroupID)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(ba.PortSpec)+1))
	buf = append(buf, []byte(ba.PortSpec)...)
	buf = append(buf, 0)
	padLen := utils.Roundup(len(buf), 4)
	padding := make([]byte, padLen-len(buf))
	buf = append(buf, padding...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(ba.ResultList)))
	w.Write(buf)
	for _, res := range ba.ResultList {
		res.Encode(w)
	}
}

func (ba *BindAck) Decode(r io.Reader) {
	buf := make([]byte, 10)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	ba.MaxXmitFrag = binary.LittleEndian.Uint16(buf[:2])
	ba.MaxRecvFrag = binary.LittleEndian.Uint16(buf[2:4])
	ba.AssocGroupID = binary.LittleEndian.Uint32(buf[4:8])
	addrLen := binary.LittleEndian.Uint16(buf[8:])
	addr := make([]byte, addrLen)
	_, err = r.Read(addr)
	if err != nil {
		return
	}

	ba.PortSpec = string(addr[:addrLen-1])
	padLen := utils.Roundup(len(buf)+int(addrLen), 4)
	padding := make([]byte, padLen-len(buf)-int(addrLen))
	_, err = r.Read(padding)
	if err != nil {
		return
	}

	resNum := make([]byte, 4)
	_, err = r.Read(resNum)
	if err != nil {
		return
	}

	ba.ResultList = make([]*Result, binary.LittleEndian.Uint32(resNum))
	for i := range ba.ResultList {
		ba.ResultList[i] = &Result{}
		ba.ResultList[i].Decode(r)
	}
}

type Request struct {
	AllocHint  uint32
	ContextID  uint16
	OpNum      uint16
	ObjectUUID []byte
}

func (req *Request) Encode(w io.Writer) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, req.AllocHint)
	buf = binary.LittleEndian.AppendUint16(buf, req.ContextID)
	buf = binary.LittleEndian.AppendUint16(buf, req.OpNum)
	if req.ObjectUUID != nil {
		buf = append(buf, req.ObjectUUID...)
	}
	w.Write(buf)
}

func (req *Request) Decode(r io.Reader) {
	buf := make([]byte, 8)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	req.AllocHint = binary.LittleEndian.Uint32(buf[:4])
	req.ContextID = binary.LittleEndian.Uint16(buf[4:6])
	req.OpNum = binary.LittleEndian.Uint16(buf[6:8])
	if req.ObjectUUID != nil {
		uuid := make([]byte, 16)
		_, err := r.Read(uuid)
		if err != nil {
			return
		}

		copy(req.ObjectUUID, uuid)
	}
}

type Response struct {
	AllocHint   uint32
	ContextID   uint16
	CancelCount uint16
}

func (resp *Response) Encode(w io.Writer) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, resp.AllocHint)
	buf = binary.LittleEndian.AppendUint16(buf, resp.ContextID)
	buf = binary.LittleEndian.AppendUint16(buf, resp.CancelCount)
	w.Write(buf)
}

func (resp *Response) Decode(r io.Reader) {
	buf := make([]byte, 8)
	_, err := r.Read(buf)
	if err != nil {
		return
	}

	resp.AllocHint = binary.LittleEndian.Uint32(buf[:4])
	resp.ContextID = binary.LittleEndian.Uint16(buf[4:6])
	resp.CancelCount = binary.LittleEndian.Uint16(buf[6:8])
}

type Frame struct {
	Handle          lsarpc.Handle
	SecurityContext ntlm.SecurityContext
}

type NetShareGetInfoRequest struct {
	Server string
	Share  string
	Level  uint32
}

func (req *NetShareGetInfoRequest) Unmarshal(buf []byte) {
	srvLength := binary.LittleEndian.Uint32(buf[12:16])
	req.Server = utils.DecodeToString(buf[16 : 16+srvLength*2-2])
	off := 16 + srvLength*2
	shLength := binary.LittleEndian.Uint32(buf[off+8 : off+12])
	req.Share = utils.DecodeToString(buf[off+12 : off+12+shLength*2-2])
	off += 12 + shLength*2
	off = uint32(utils.Roundup(int(off), 4))
	req.Level = binary.LittleEndian.Uint32(buf[off : off+4])
}

type NetShareInfo1Response struct {
	Share   string
	Type    uint32
	Comment string
	Result  uint32
}

func (resp *NetShareInfo1Response) MarshalNDR(ctx context.Context, w ndr.Writer) error {
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020004)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020008)
	buf = binary.LittleEndian.AppendUint32(buf, resp.Type)
	buf = binary.LittleEndian.AppendUint32(buf, 0x0002000c)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(resp.Share)+1))
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(resp.Share)+1))
	buf = append(buf, utils.EncodeStringToBytes(resp.Share)...)
	buf = append(buf, 0, 0)
	padLen := utils.Roundup(len(buf), 4) - len(buf)
	padding := make([]byte, padLen)
	buf = append(buf, padding...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(resp.Comment)+1))
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(resp.Comment)+1))
	buf = append(buf, utils.EncodeStringToBytes(resp.Comment)...)
	buf = append(buf, 0, 0)
	padLen = utils.Roundup(len(buf), 4) - len(buf)
	padding = make([]byte, padLen)
	buf = append(buf, padding...)
	buf = binary.LittleEndian.AppendUint32(buf, resp.Result)
	_, err := w.Write(buf)
	return err
}

type MdsOpenRequest struct {
	DeviceID       uint32
	Unkn2          uint32
	Unkn3          uint32
	ShareMountPath string
	ShareName      string
	MaxCount       uint32
}

func (req *MdsOpenRequest) Unmarshal(buf []byte) {
	req.DeviceID = binary.LittleEndian.Uint32(buf[:4])
	req.Unkn2 = binary.LittleEndian.Uint32(buf[4:8])
	req.Unkn3 = binary.LittleEndian.Uint32(buf[8:12])
	req.MaxCount = binary.LittleEndian.Uint32(buf[12:16])
	smpLen := binary.LittleEndian.Uint32(buf[20:24])
	req.ShareMountPath = string(buf[24 : 24+smpLen-1])
	off := 24 + smpLen
	off = uint32(utils.Roundup(int(off), 4))
	snLen := binary.LittleEndian.Uint32(buf[off+8 : off+12])
	req.ShareName = string(buf[off+12 : off+12+snLen-1])
}

type MdsOpenResponse struct {
	DeviceID     uint32
	Unkn2        uint32
	Unkn3        uint32
	SharePath    string
	PolicyHandle [20]byte
	MaxCount     uint32
}

func (resp *MdsOpenResponse) MarshalNDR(ctx context.Context, w ndr.Writer) error {
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, resp.DeviceID)
	buf = binary.LittleEndian.AppendUint32(buf, resp.Unkn2)
	buf = binary.LittleEndian.AppendUint32(buf, resp.Unkn3)
	buf = binary.LittleEndian.AppendUint32(buf, resp.MaxCount)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(resp.SharePath)+1))
	buf = append(buf, []byte(resp.SharePath)...)
	buf = append(buf, 0)
	padLen := utils.Roundup(len(buf), 4) - len(buf)
	padding := make([]byte, padLen)
	buf = append(buf, padding...)
	buf = append(buf, resp.PolicyHandle[:]...)
	_, err := w.Write(buf)
	return err
}
