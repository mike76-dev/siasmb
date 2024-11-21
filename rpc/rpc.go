// A minimal implementation of MS-RPC protocol
package rpc

import (
	"io"
	"log"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	"github.com/oiweiwei/go-msrpc/ndr"
)

const (
	LSA_CLOSE         = 0x0000
	LSA_LOOKUP_NAMES  = 0x000e
	LSA_OPEN_POLICY_2 = 0x002c
	LSA_GET_USER_NAME = 0x002d
)

type ResponseBody struct {
	Header  Response
	Payload ndr.Marshaler
}

func (rb *ResponseBody) Encode(w io.Writer) {
	payload, err := ndr.Marshal(rb.Payload)
	if err != nil {
		log.Println("Error encoding response:", err)
		return
	}

	rb.Header.AllocHint = uint32(len(payload))
	rb.Header.Encode(w)
	w.Write(payload)
}

func NewBindAck(callID uint32, addr string) *OutboundPacket {
	packet := &OutboundPacket{
		Header: NewHeader(PACKET_TYPE_BIND_ACK, PFC_FIRST_FRAG|PFC_LAST_FRAG, callID),
		Body: &BindAck{
			MaxXmitFrag: 0xffff,
			MaxRecvFrag: 0xffff,
			PortSpec:    addr,
			ResultList: []*Result{
				{
					TransferSyntax: &SyntaxID{
						IfUUID:         [16]byte(LSARPC),
						IfVersionMajor: 2,
						IfVersionMinor: 0,
					},
				},
			},
		},
	}

	return packet
}

func NewGetUserNameResponse(callID uint32, accountName, authorityName string, status uint32) *OutboundPacket {
	packet := &OutboundPacket{
		Header: NewHeader(PACKET_TYPE_RESPONSE, PFC_FIRST_FRAG|PFC_LAST_FRAG, callID),
		Body: &ResponseBody{
			Payload: &lsarpc.GetUserNameResponse{
				UserName: &dtyp.UnicodeString{
					Length:        uint16(len(accountName) * 2),
					MaximumLength: uint16(len(accountName) * 2),
					Buffer:        accountName,
				},
				DomainName: &dtyp.UnicodeString{
					Length:        uint16(len(authorityName) * 2),
					MaximumLength: uint16(len(authorityName) * 2),
					Buffer:        authorityName,
				},
				Return: int32(status),
			},
		},
	}

	return packet
}

func NewOpenPolicy2Response(callID uint32, frame *Frame, status uint32) *OutboundPacket {
	packet := &OutboundPacket{
		Header: NewHeader(PACKET_TYPE_RESPONSE, PFC_FIRST_FRAG|PFC_LAST_FRAG, callID),
		Body: &ResponseBody{
			Payload: &lsarpc.OpenPolicy2Response{
				Policy: &frame.Handle,
				Return: int32(status),
			},
		},
	}

	return packet
}

func NewLookupNamesResponse(callID uint32, ctx ntlm.SecurityContext, status uint32) *OutboundPacket {
	packet := &OutboundPacket{
		Header: NewHeader(PACKET_TYPE_RESPONSE, PFC_FIRST_FRAG|PFC_LAST_FRAG, callID),
		Body: &ResponseBody{
			Payload: &lsarpc.LookupNamesResponse{
				ReferencedDomains: &lsarpc.ReferencedDomainList{
					Entries:    1,
					MaxEntries: 32,
					Domains: []*lsarpc.TrustInformation{
						{
							Name: &dtyp.UnicodeString{
								Length:        uint16(len(ctx.Domain) * 2),
								MaximumLength: uint16(len(ctx.Domain)*2 + 2),
								Buffer:        ctx.Domain,
							},
							SID: ctx.DomainSID,
						},
					},
				},
				TranslatedSIDs: &lsarpc.TranslatedSIDs{
					Entries: 1,
					SIDs: []*lsarpc.TranslatedSID{
						{
							Use:         lsarpc.SIDNameUseTypeUser,
							RelativeID:  ctx.UserRID,
							DomainIndex: 0,
						},
					},
				},
				MappedCount: 1,
				Return:      int32(status),
			},
		},
	}

	return packet
}

func NewCloseResponse(callID uint32, status uint32) *OutboundPacket {
	packet := &OutboundPacket{
		Header: NewHeader(PACKET_TYPE_RESPONSE, PFC_FIRST_FRAG|PFC_LAST_FRAG, callID),
		Body: &ResponseBody{
			Payload: &lsarpc.CloseResponse{
				Return: int32(status),
			},
		},
	}

	return packet
}
