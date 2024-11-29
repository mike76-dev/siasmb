package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/rpc"
	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/spnego"
	"github.com/mike76-dev/siasmb/utils"
	"github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	"github.com/oiweiwei/go-msrpc/ndr"
	"go.sia.tech/renterd/api"
)

var (
	errRequestNotWithinWindow        = errors.New("request out of command sequence window")
	errCommandSecuenceWindowExceeded = errors.New("command sequence window exceeded")
	errLongRequest                   = errors.New("request too long")
	errAlreadyNegotiated             = errors.New("dialect already negotiated")
	errInvalidSignature              = errors.New("invalid signature")
)

type connection struct {
	commandSequenceWindow map[uint64]struct{}
	requestList           map[uint64]*smb2.Request
	pendingResponses      map[uint64]smb2.GenericResponse
	clientCapabilities    uint32
	negotiateDialect      uint16
	asyncCommandList      map[uint64]*smb2.Request
	dialect               string
	shouldSign            bool
	clientName            string
	maxTransactSize       uint64
	maxWriteSize          uint64
	maxReadSize           uint64
	supportsMultiCredit   bool
	sessionTable          map[uint64]*session
	creationTime          time.Time

	conn       net.Conn
	mu         sync.Mutex
	server     *server
	ntlmServer *ntlm.Server
	writeChan  chan []byte
	closeChan  chan struct{}
	once       sync.Once
	stopChans  map[uint64]chan struct{}
}

func (c *connection) grantCredits(mid uint64, numCredits uint16) error {
	max, _ := utils.FindMaxKey(c.commandSequenceWindow)
	if max == 0 {
		max = mid
	}

	if uint64(numCredits) > math.MaxUint64-max {
		return errCommandSecuenceWindowExceeded
	}

	var i uint64
	for i = 0; i < uint64(numCredits); i++ {
		c.commandSequenceWindow[max+i+1] = struct{}{}
	}

	return nil
}

func (c *connection) acceptRequest(msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if uint64(len(msg)) > c.maxTransactSize+256 {
		return errLongRequest
	}

	cid := make([]byte, 8)
	rand.Read(cid)

	reqs, err := smb2.GetRequests(msg, binary.LittleEndian.Uint64(cid))
	if err != nil {
		return err
	}

	var ss *session
	var found bool
	for i, req := range reqs {
		var mid uint64
		if req.Header().IsSmb() {
			if c.negotiateDialect != smb2.SMB_DIALECT_UNKNOWN || len(reqs) > 1 {
				return smb2.ErrWrongProtocol
			}
			c.grantCredits(mid, 1)
		} else {
			mid = req.Header().MessageID()
			credits := req.Header().CreditRequest()
			if credits == 0 {
				credits = 1
			}

			c.grantCredits(mid, credits)
			if req.Header().Command() == smb2.SMB2_CANCEL {
				if err := c.cancelRequest(req); err != nil {
					log.Printf("Couldn't cancel request %d:, %v\n", req.Header().Command(), err)
				}

				continue
			}
		}

		_, ok := c.commandSequenceWindow[mid]
		if !ok {
			return errRequestNotWithinWindow
		}

		if mid == math.MaxUint64 {
			return errCommandSecuenceWindowExceeded
		}

		if i == 0 || req.GroupID() == 0 {
			ss, found = c.sessionTable[req.Header().SessionID()]
		}

		if found && !ss.validateRequest(req) {
			return errInvalidSignature
		}

		delete(c.commandSequenceWindow, mid)
		c.requestList[mid] = req
	}

	return nil
}

func (c *connection) processRequest(req *smb2.Request) (smb2.GenericResponse, *session, error) {
	if req.Header().IsSmb() && req.Header().LegacyCommand() == smb2.SMB_COM_NEGOTIATE {
		nr := smb2.NegotiateRequest{Request: *req}
		if err := nr.Validate(); err != nil {
			if errors.Is(err, smb2.ErrDialectNotSupported) {
				resp := smb2.NegotiateErrorResponse(smb2.STATUS_NOT_SUPPORTED)
				return resp, nil, nil
			}
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NegotiateErrorResponse(smb2.STATUS_INVALID_PARAMETER)
				return resp, nil, nil
			}
			log.Println("Invalid SMB_COM_NEGOTIATE request:", err)
			return nil, nil, err
		}

		resp := smb2.NewNegotiateResponse(c.server.serverGuid[:], c.ntlmServer)
		return resp, nil, nil
	}

	switch req.Header().Command() {
	case smb2.SMB2_NEGOTIATE:
		if c.negotiateDialect != smb2.SMB_DIALECT_UNKNOWN {
			log.Println("Error: repeated SMB2_NEGOTIATE request received")
			return nil, nil, errAlreadyNegotiated
		}

		nr := smb2.NegotiateRequest{Request: *req}
		if err := nr.Validate(); err != nil {
			if errors.Is(err, smb2.ErrDialectNotSupported) {
				resp := smb2.NewErrorResponse(nr, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, nil, nil
			}
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(nr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			log.Println("Invalid SMB2_NEGOTIATE request:", err)
			return nil, nil, err
		}

		c.clientCapabilities = nr.Capabilities()
		c.dialect = "2.0.2"
		c.negotiateDialect = smb2.SMB_DIALECT_202
		if nr.SecurityMode()&smb2.NEGOTIATE_SIGNING_REQUIRED > 0 {
			c.shouldSign = true
		}

		resp := &smb2.NegotiateResponse{}
		resp.FromRequest(nr)
		resp.Generate(c.server.serverGuid[:], c.ntlmServer)

		return resp, nil, nil

	case smb2.SMB2_SESSION_SETUP:
		ssr := smb2.SessionSetupRequest{Request: *req}
		if err := ssr.Validate(); err != nil {
			log.Println("Invalid SMB2_SESSION_SETUP request:", err)
			return nil, nil, err
		}

		ss, found, err := c.server.registerSession(c, ssr)
		if err != nil {
			if errors.Is(err, errSessionNotFound) {
				resp := smb2.NewErrorResponse(ssr, smb2.STATUS_USER_SESSION_DELETED, nil)
				return resp, nil, nil
			} else {
				log.Println("Error registering session:", err)
				return nil, nil, err
			}
		}

		var token []byte
		if found {
			authToken, err := spnego.DecodeNegTokenResp(ssr.SecurityBuffer())
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				log.Println("Couldn't decode AUTHENTICATE token:", err)
				return nil, nil, err
			}

			if err := c.ntlmServer.Authenticate(authToken.ResponseToken); err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				c.server.mu.Lock()
				c.server.stats.pwErrors++
				c.server.mu.Unlock()
				resp := smb2.NewErrorResponse(ssr, smb2.STATUS_NO_SUCH_USER, nil)
				return resp, nil, nil
			}

			ss.validate(ssr)
			ss.idleTime = time.Now()
			token = spnego.FinalNegTokenResp
		} else {
			negToken, err := spnego.DecodeNegTokenInit(ssr.SecurityBuffer())
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				log.Println("Couldn't decode NEGOTIATE token:", err)
				return nil, nil, err
			}

			challenge, err := c.ntlmServer.Challenge(negToken.MechToken)
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				log.Println("Couldn't generate CHALLENGE:", err)
				return nil, nil, err
			}

			token, err = spnego.EncodeNegTokenResp(0x01, spnego.NlmpOid, challenge, nil)
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				log.Println("Couldn't generate CHALLENGE token:", err)
				return nil, nil, err
			}
		}

		var flags uint16
		if ss.state == sessionValid {
			switch strings.ToLower(ss.userName) {
			case "":
				flags = smb2.SESSION_FLAG_IS_NULL
			case "guest":
				flags = smb2.SESSION_FLAG_IS_GUEST
			default:
			}
		}

		resp := &smb2.SessionSetupResponse{}
		resp.FromRequest(ssr)
		resp.Generate(ss.sessionID, flags, token, found)
		if !found {
			resp.Header().SetCreditResponse(1)
		}

		return resp, ss, nil

	case smb2.SMB2_LOGOFF:
		lr := smb2.LogoffRequest{Request: *req}
		if err := lr.Validate(); err != nil {
			log.Println("Invalid SMB2_LOGOFF request:", err)
			return nil, nil, err
		}

		ss, err := c.server.deregisterSession(c, req.Header().SessionID())
		if err != nil {
			if errors.Is(err, errSessionNotFound) {
				resp := smb2.NewErrorResponse(lr, smb2.STATUS_USER_SESSION_DELETED, nil)
				return resp, nil, nil
			} else {
				log.Println("Error deregistering session:", err)
				return nil, nil, err
			}
		}

		resp := &smb2.LogoffResponse{}
		resp.FromRequest(lr)

		return resp, ss, nil

	case smb2.SMB2_TREE_CONNECT:
		tcr := smb2.TreeConnectRequest{Request: *req}
		if err := tcr.Validate(); err != nil {
			log.Println("Invalid SMB2_TREE_CONNECT request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[tcr.Header().SessionID()]
		c.mu.Unlock()
		if !found {
			resp := smb2.NewErrorResponse(tcr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.idleTime = time.Now()
		tc, err := c.newTreeConnect(ss, tcr.PathName())
		if err != nil {
			if errors.Is(err, errNoShare) {
				resp := smb2.NewErrorResponse(tcr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, ss, nil
			}
			if errors.Is(err, errAccessDenied) {
				resp := smb2.NewErrorResponse(tcr, smb2.STATUS_ACCESS_DENIED, nil)
				return resp, ss, nil
			}
		}

		resp := &smb2.TreeConnectResponse{}
		resp.FromRequest(tcr)
		resp.Generate(tc.treeID, uint8(tc.share.shareType), tc.maximalAccess)

		return resp, ss, nil

	case smb2.SMB2_TREE_DISCONNECT:
		tdr := smb2.TreeDisconnectRequest{Request: *req}
		if err := tdr.Validate(); err != nil {
			log.Println("Invalid SMB2_TREE_DISCONNECT request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[tdr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(tdr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.idleTime = time.Now()
		if err := ss.closeTreeConnect(tdr.Header().TreeID()); err != nil {
			resp := smb2.NewErrorResponse(tdr, smb2.STATUS_NETWORK_NAME_DELETED, nil)
			return resp, ss, nil
		}

		resp := &smb2.TreeDisconnectResponse{}
		resp.FromRequest(tdr)

		return resp, ss, nil

	case smb2.SMB2_CREATE:
		cr := smb2.CreateRequest{Request: *req}
		if err := cr.Validate(); err != nil {
			log.Println("Invalid SMB2_CREATE request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[cr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		ss.idleTime = time.Now()
		tc, found := ss.treeConnectTable[cr.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		contexts, err := cr.CreateContexts()
		if err != nil {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		path := cr.Filename()
		co := cr.CreateOptions()
		if co&smb2.FILE_DELETE_ON_CLOSE > 0 && (tc.maximalAccess&(smb2.DELETE|smb2.GENERIC_ALL|smb2.GENERIC_EXECUTE|smb2.GENERIC_READ|smb2.GENERIC_WRITE) == 0) {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		if co&smb2.FILE_NO_INTERMEDIATE_BUFFERING > 0 {
			da := cr.DesiredAccess()
			cr.SetDesiredAccess(da &^ smb2.FILE_APPEND_DATA)
		}

		co = co &^ smb2.FILE_COMPLETE_IF_OPLOCKED
		co = co &^ smb2.FILE_SYNCHRONOUS_IO_ALERT
		co = co &^ smb2.FILE_SYNCHRONOUS_IO_NONALERT
		co = co &^ smb2.FILE_OPEN_FOR_FREE_SPACE_QUERY
		cr.SetCreateOptions(co)

		ctx, cancel := context.WithCancel(context.Background())
		var info api.ObjectMetadata
		var result uint32
		var restored bool
		var op *open
		if tc.share.name == "ipc$" {
			switch strings.ToLower(path) {
			case "srvsvc", "lsarpc", "mdssvc":
				info = api.ObjectMetadata{Name: path}
				result = smb2.FILE_OPENED
			default:
				cancel()
				c.server.mu.Lock()
				c.server.stats.permErrors++
				c.server.mu.Unlock()
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_ACCESS_DENIED, nil)
				return resp, ss, nil
			}
		} else {
			access := grantAccess(cr, tc, ss)
			if !access {
				cancel()
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_ACCESS_DENIED, nil)
				c.server.mu.Lock()
				c.server.stats.permErrors++
				c.server.mu.Unlock()
				return resp, ss, nil
			}

			info, err = tc.share.client.GetObjectInfo(ctx, tc.share.bucket, path)
			if err != nil {
				log.Printf("Error getting object info (bucket: %s, path: %s): %v\n", tc.share.bucket, path, err)
				if errors.Is(err, context.DeadlineExceeded) {
					cancel()
					resp := smb2.NewErrorResponse(cr, smb2.STATUS_IO_TIMEOUT, nil)
					return resp, ss, nil
				}
			}

			switch cr.CreateDisposition() {
			case smb2.FILE_SUPERSEDE:
				if err != nil {
					tc.mu.Lock()
					op, restored = tc.persistedOpens[path]
					tc.mu.Unlock()
					if !restored {
						info = api.ObjectMetadata{Name: "/" + path, ModTime: api.TimeRFC3339(time.Now())}
						result = smb2.FILE_CREATED
					} else {
						result = smb2.FILE_SUPERSEDED
					}
				} else {
					result = smb2.FILE_SUPERSEDED
				}
			case smb2.FILE_OPEN:
				if err != nil {
					tc.mu.Lock()
					op, restored = tc.persistedOpens[path]
					tc.mu.Unlock()
					if !restored {
						cancel()
						resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_NOT_FOUND, nil)
						return resp, ss, nil
					} else {
						result = smb2.FILE_OPENED
					}
				} else {
					result = smb2.FILE_OPENED
				}
			case smb2.FILE_CREATE:
				if err != nil {
					info = api.ObjectMetadata{Name: "/" + path, ModTime: api.TimeRFC3339(time.Now())}
					result = smb2.FILE_CREATED
					if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE > 0 {
						info.Name += "/"
						if err := tc.share.client.MakeDirectory(ctx, tc.share.bucket, path); err != nil {
							resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_NOT_FOUND, nil)
							return resp, ss, nil
						}
					}
				} else {
					cancel()
					resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_COLLISION, nil)
					return resp, ss, nil
				}
			case smb2.FILE_OPEN_IF:
				if err != nil {
					tc.mu.Lock()
					op, restored = tc.persistedOpens[path]
					tc.mu.Unlock()
					if !restored {
						info = api.ObjectMetadata{Name: "/" + path, ModTime: api.TimeRFC3339(time.Now())}
						result = smb2.FILE_CREATED
						if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE > 0 {
							info.Name += "/"
							if err := tc.share.client.MakeDirectory(ctx, tc.share.bucket, path); err != nil {
								resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_NOT_FOUND, nil)
								return resp, ss, nil
							}
						}
					} else {
						result = smb2.FILE_OPENED
					}
				} else {
					result = smb2.FILE_OPENED
				}
			case smb2.FILE_OVERWRITE:
				if err != nil {
					tc.mu.Lock()
					op, restored = tc.persistedOpens[path]
					tc.mu.Unlock()
					if !restored {
						cancel()
						resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_NOT_FOUND, nil)
						return resp, ss, nil
					} else {
						result = smb2.FILE_OVERWRITTEN
					}
				} else {
					result = smb2.FILE_OVERWRITTEN
				}
			case smb2.FILE_OVERWRITE_IF:
				if err != nil {
					tc.mu.Lock()
					op, restored = tc.persistedOpens[path]
					tc.mu.Unlock()
					if !restored {
						info = api.ObjectMetadata{Name: "/" + path, ModTime: api.TimeRFC3339(time.Now())}
						result = smb2.FILE_CREATED
						if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE > 0 {
							info.Name += "/"
							if err := tc.share.client.MakeDirectory(ctx, tc.share.bucket, path); err != nil {
								resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_NOT_FOUND, nil)
								return resp, ss, nil
							}
						}
					} else {
						result = smb2.FILE_OVERWRITTEN
					}
				} else {
					result = smb2.FILE_OVERWRITTEN
				}
			}
		}

		if restored {
			c.server.restoreOpen(op)
		} else {
			op = ss.registerOpen(cr, tc, info, ctx, cancel)
			if op == nil {
				cancel()
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, ss, nil
			}
		}

		if result == smb2.FILE_CREATED {
			tc.mu.Lock()
			tc.persistedOpens[path] = op
			tc.mu.Unlock()
		}

		if result == smb2.FILE_SUPERSEDED || result == smb2.FILE_OVERWRITTEN {
			op.size = 0
			op.allocated = 0
			op.lastModified = time.Now()
		}

		respContexts := make(map[uint32][]byte)
		for id, ctx := range contexts {
			switch id {
			case smb2.CREATE_EA_BUFFER:
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_EAS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			case smb2.CREATE_QUERY_MAXIMAL_ACCESS_REQUEST:
				respContexts[id] = smb2.HandleCreateQueryMaximalAccessRequest(ctx, op.lastModified, op.grantedAccess)
			case smb2.CREATE_QUERY_ON_DISK_ID:
				respContexts[id] = smb2.HandleCreateQueryOnDiskID(op.handle, tc.share.volumeID)
			case smb2.CREATE_ALLOCATION_SIZE:
				op.allocated = binary.LittleEndian.Uint64(ctx)
			}
		}

		resp := &smb2.CreateResponse{}
		resp.FromRequest(cr)
		resp.Generate(
			op.oplockLevel,
			result,
			op.size,
			op.allocated,
			op.lastModified,
			op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY > 0,
			op.fileID,
			op.durableFileID,
			respContexts,
		)

		gid := req.GroupID()
		if gid > 0 {
			resp.SetOpenID(op.id())
		}

		return resp, ss, nil

	case smb2.SMB2_CLOSE:
		cr := smb2.CloseRequest{Request: *req}
		if err := cr.Validate(); err != nil {
			log.Println("Invalid SMB2_CLOSE request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[cr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		ss.idleTime = time.Now()
		tc, found := ss.treeConnectTable[cr.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		id := cr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		var op *open
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()

		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		req.SetOpenID(id)
		if op.createOptions&smb2.FILE_DELETE_ON_CLOSE > 0 {
			if err := tc.share.client.DeleteObject(op.ctx, tc.share.bucket, op.pathName, op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY > 0); err != nil {
				log.Println("Error deleting object:", err)
			}
		}

		c.server.closeOpen(op)

		toNotify := make(map[uint64]*smb2.Request)
		c.mu.Lock()
		for aid, r := range c.asyncCommandList {
			if r.Header().Command() == smb2.SMB2_CHANGE_NOTIFY && bytes.Equal(r.OpenID(), id) {
				toNotify[aid] = r
				delete(c.asyncCommandList, aid)
			}
		}
		c.mu.Unlock()

		for aid, r := range toNotify {
			resp := smb2.NewErrorResponse(r, smb2.STATUS_NOTIFY_CLEANUP, nil)
			resp.Header().ClearFlag(smb2.FLAGS_RELATED_OPERATIONS)
			resp.Header().SetAsyncID(aid)
			c.server.writeResponse(c, ss, resp)
		}

		resp := &smb2.CloseResponse{}
		resp.FromRequest(cr)
		resp.Generate(op.lastModified, op.size, op.allocated, op.fileAttributes)

		return resp, ss, nil

	case smb2.SMB2_FLUSH:
		fr := smb2.FlushRequest{Request: *req}
		if err := fr.Validate(); err != nil {
			log.Println("Invalid SMB2_FLUSH request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[fr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(fr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		resp := &smb2.FlushResponse{}
		resp.FromRequest(fr)

		return resp, ss, nil

	case smb2.SMB2_READ:
		rr := smb2.ReadRequest{Request: *req}
		if err := rr.Validate(); err != nil {
			log.Println("Invalid SMB2_READ request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[rr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		tc, found := ss.treeConnectTable[rr.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		ss.idleTime = time.Now()
		if rr.Length() > uint32(c.maxReadSize) {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		var op *open
		id := rr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(rr, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		req.SetOpenID(id)

		if op.grantedAccess&smb2.FILE_READ_DATA == 0 {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		if strings.ToLower(op.fileName) == "srvsvc" {
			if op.srvsrcData != nil {
				ip := rpc.InboundPacket{}
				ip.Read(bytes.NewBuffer(op.srvsrcData))

				var packet *rpc.OutboundPacket
				switch ip.Header.PacketType {
				case rpc.PACKET_TYPE_BIND:
					body := ip.Body.(*rpc.Bind)
					packet = rpc.NewBindAck(ip.Header.CallID, "\\pipe\\srvsvc", body.ContextList)
				default:
				}

				var buf bytes.Buffer
				packet.Write(&buf)
				resp := &smb2.ReadResponse{}
				resp.FromRequest(rr)
				resp.Generate(buf.Bytes(), rr.Padding())
				op.srvsrcData = nil
				return resp, ss, nil
			}
		}

		if rr.Offset() >= op.size {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_END_OF_FILE, nil)
			return resp, ss, nil
		}

		aid := make([]byte, 8)
		rand.Read(aid)
		asyncID := binary.LittleEndian.Uint64(aid)
		c.mu.Lock()
		c.asyncCommandList[asyncID] = req
		c.mu.Unlock()

		resp := smb2.NewErrorResponse(rr, smb2.STATUS_PENDING, nil)
		resp.Header().SetAsyncID(asyncID)
		resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
		resp.Header().ClearFlag(smb2.FLAGS_RELATED_OPERATIONS)
		resp.Header().ClearFlag(smb2.FLAGS_SIGNED)
		resp.Header()[len(resp.Header())-1] = 0x21

		go func() {
			length := uint64(rr.Length())
			if rr.Offset()+length >= op.size {
				length = op.size - rr.Offset()
			}

			var resp smb2.GenericResponse
			var data bytes.Buffer
			if err := tc.share.client.ReadObject(op.ctx, tc.share.bucket, op.pathName, rr.Offset(), length, &data); err != nil {
				log.Println("Error reading object:", err)
				resp = smb2.NewErrorResponse(rr, smb2.STATUS_DATA_ERROR, nil)
			} else if data.Len() < int(rr.MinimumCount()) {
				resp = smb2.NewErrorResponse(rr, smb2.STATUS_END_OF_FILE, nil)
			} else {
				resp = &smb2.ReadResponse{}
				resp.FromRequest(rr)
				resp.(*smb2.ReadResponse).Generate(data.Bytes(), rr.Padding())
				resp.Header().SetAsyncID(asyncID)
				resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
			}

			c.mu.Lock()
			delete(c.requestList, resp.Header().MessageID())
			delete(c.asyncCommandList, asyncID)
			c.mu.Unlock()

			c.server.writeResponse(c, ss, resp)
		}()

		return resp, ss, nil

	case smb2.SMB2_WRITE:
		wr := smb2.WriteRequest{Request: *req}
		if err := wr.Validate(); err != nil {
			log.Println("Invalid SMB2_WRITE request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[wr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(wr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		tc, found := ss.treeConnectTable[wr.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(wr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		ss.idleTime = time.Now()
		length := uint64(len(wr.Buffer()))
		if length > c.maxWriteSize {
			resp := smb2.NewErrorResponse(wr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		var op *open
		id := wr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(wr, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		req.SetOpenID(id)
		if op.fileName != "" && op.fileName[0] == '.' {
			resp := &smb2.WriteResponse{}
			resp.FromRequest(wr)
			resp.Generate(uint32(len(wr.Buffer())))
			return resp, ss, nil
		}

		if (length <= op.size && op.grantedAccess&smb2.FILE_WRITE_DATA == 0) || op.grantedAccess&smb2.FILE_APPEND_DATA == 0 {
			resp := smb2.NewErrorResponse(wr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		if strings.ToLower(op.fileName) == "srvsvc" {
			buf := make([]byte, len(wr.Buffer()))
			copy(buf, wr.Buffer())
			op.mu.Lock()
			op.srvsrcData = buf
			op.mu.Unlock()
			resp := &smb2.WriteResponse{}
			resp.FromRequest(wr)
			resp.Generate(uint32(len(buf)))
			return resp, ss, nil
		}

		if op.pendingUpload == nil {
			id, err := tc.share.client.StartUpload(op.ctx, tc.share.bucket, op.pathName)
			if err != nil {
				resp := smb2.NewErrorResponse(wr, smb2.STATUS_DATA_ERROR, nil)
				return resp, ss, nil
			}

			op.pendingUpload = &upload{uploadID: id}
		}

		aid := make([]byte, 8)
		rand.Read(aid)
		asyncID := binary.LittleEndian.Uint64(aid)
		c.mu.Lock()
		c.asyncCommandList[asyncID] = req
		c.mu.Unlock()

		resp := smb2.NewErrorResponse(wr, smb2.STATUS_PENDING, nil)
		resp.Header().SetAsyncID(asyncID)
		resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
		resp.Header().ClearFlag(smb2.FLAGS_RELATED_OPERATIONS)
		resp.Header().ClearFlag(smb2.FLAGS_SIGNED)
		resp.Header()[len(resp.Header())-1] = 0x21

		go func() {
			var resp smb2.GenericResponse
			r := bytes.NewReader(wr.Buffer())
			if op.pendingUpload == nil {
				resp = smb2.NewErrorResponse(wr, smb2.STATUS_NOT_SUPPORTED, nil)
			} else {
				op.pendingUpload.mu.Lock()
				op.pendingUpload.partCount++
				count := op.pendingUpload.partCount
				op.pendingUpload.mu.Unlock()
				eTag, err := tc.share.client.UploadPart(
					op.ctx,
					r,
					tc.share.bucket,
					op.pathName,
					op.pendingUpload.uploadID,
					count,
					wr.Offset(),
					uint64(len(wr.Buffer())),
				)
				if err != nil {
					log.Println("Error writing data:", err)
					resp = smb2.NewErrorResponse(wr, smb2.STATUS_DATA_ERROR, nil)
				} else {
					if op.pendingUpload != nil {
						op.pendingUpload.mu.Lock()
						op.pendingUpload.parts = append(op.pendingUpload.parts, api.MultipartCompletedPart{
							PartNumber: count,
							ETag:       eTag,
						})
						op.pendingUpload.totalSize += uint64(len(wr.Buffer()))
						size := op.pendingUpload.totalSize
						op.pendingUpload.mu.Unlock()
						if (op.size > 0 && size >= op.size) || (op.allocated > 0 && size >= op.allocated) {
							eTag, err = tc.share.client.FinishUpload(
								op.ctx,
								tc.share.bucket,
								op.pathName,
								op.pendingUpload.uploadID,
								op.pendingUpload.parts,
							)
							if err != nil {
								log.Println("Error completing write:", err)
								resp = smb2.NewErrorResponse(wr, smb2.STATUS_DATA_ERROR, nil)
							} else {
								op.size = size
								op.allocated = size
								op.pendingUpload = nil
								buf, err := hex.DecodeString(eTag)
								if err == nil && len(buf) >= 8 {
									op.handle = binary.LittleEndian.Uint64(buf[:8])
								}
							}
						}

						resp = &smb2.WriteResponse{}
						resp.FromRequest(wr)
						resp.(*smb2.WriteResponse).Generate(uint32(len(wr.Buffer())))
						resp.Header().SetAsyncID(asyncID)
						resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
					}
				}
			}

			c.mu.Lock()
			delete(c.requestList, resp.Header().MessageID())
			delete(c.asyncCommandList, asyncID)
			c.mu.Unlock()

			c.server.writeResponse(c, ss, resp)
		}()

		return resp, ss, nil

	case smb2.SMB2_LOCK:
		lr := smb2.LockRequest{Request: *req}
		if err := lr.Validate(); err != nil {
			log.Println("Invalid SMB2_LOCK request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[lr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(lr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		resp := &smb2.LockResponse{}
		resp.FromRequest(lr)

		return resp, ss, nil

	case smb2.SMB2_IOCTL:
		ir := smb2.IoctlRequest{Request: *req}
		if err := ir.Validate(); err != nil {
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			log.Println("Invalid SMB2_IOCTL request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[ir.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		tc, found := ss.treeConnectTable[ir.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		ss.idleTime = time.Now()
		if ir.MaxInputResponse() > uint32(c.maxTransactSize) || ir.MaxOutputResponse() > uint32(c.maxTransactSize) || len(ir.InputBuffer()) > int(c.maxTransactSize) {
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		if ir.Flags()&smb2.IOCTL_IS_FSCTL == 0 {
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

		switch ir.CtlCode() {
		case smb2.FSCTL_VALIDATE_NEGOTIATE_INFO:
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_FILE_CLOSED, nil)
			return resp, ss, nil
		case smb2.FSCTL_DFS_GET_REFERRALS:
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_FOUND, nil)
			return resp, ss, nil
		case smb2.FSCTL_PIPE_TRANSCEIVE:
			if tc.share.name != "ipc$" {
				resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			}

			var op *open
			id := ir.FileID()
			fid := binary.LittleEndian.Uint64(id[:8])
			dfid := binary.LittleEndian.Uint64(id[8:16])
			ss.mu.Lock()
			op, found = ss.openTable[fid]
			ss.mu.Unlock()
			if !found || op.durableFileID != dfid {
				if req.GroupID() > 0 {
					op = c.findOpen(req.GroupID())
				}

				if op == nil {
					resp := smb2.NewErrorResponse(ir, smb2.STATUS_FILE_CLOSED, nil)
					return resp, ss, nil
				}

				id = op.id()
			}

			req.SetOpenID(id)
			ip := rpc.InboundPacket{}
			ip.Read(bytes.NewBuffer(ir.InputBuffer()))

			var packet *rpc.OutboundPacket
			name := strings.ToLower(op.fileName)
			switch ip.Header.PacketType {
			case rpc.PACKET_TYPE_BIND:
				var addr string
				switch name {
				case "lsarpc":
					addr = "\\pipe\\lsass"
				case "srvsvc":
					addr = "\\pipe\\srvsvc"
				case "mdssvc":
					addr = "\\pipe\\mdssvc"
				}

				body := ip.Body.(*rpc.Bind)
				packet = rpc.NewBindAck(ip.Header.CallID, addr, body.ContextList)

			case rpc.PACKET_TYPE_REQUEST:
				body := ip.Body.(*rpc.Request)
				switch name {
				case "lsarpc":
					switch body.OpNum {
					case rpc.LSA_GET_USER_NAME:
						packet = rpc.NewGetUserNameResponse(
							ip.Header.CallID,
							c.ntlmServer.Session().User(),
							c.ntlmServer.Session().Domain(),
							smb2.STATUS_OK,
						)

					case rpc.LSA_OPEN_POLICY_2:
						ctx := ss.securityContext
						frame := op.newLSAFrame(ctx)
						packet = rpc.NewOpenPolicy2Response(
							ip.Header.CallID,
							frame,
							smb2.STATUS_OK,
						)

					case rpc.LSA_LOOKUP_NAMES:
						var request lsarpc.LookupNamesRequest
						if err := ndr.Unmarshal(ip.Payload, &request); err != nil {
							log.Println("Error decoding request:", err)
						} else {
							op.mu.Lock()
							frame, ok := op.lsaFrames[request.Policy.UUID.Data1]
							op.mu.Unlock()
							if !ok {
								resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
								return resp, ss, nil
							}

							packet = rpc.NewLookupNamesResponse(
								ip.Header.CallID,
								frame.SecurityContext,
								smb2.STATUS_OK,
							)
						}

					case rpc.LSA_CLOSE:
						var request lsarpc.CloseRequest
						if err := ndr.Unmarshal(ip.Payload, &request); err != nil {
							log.Println("Error decoding request:", err)
						} else {
							op.mu.Lock()
							_, ok := op.lsaFrames[request.Object.UUID.Data1]
							delete(op.lsaFrames, request.Object.UUID.Data1)
							op.mu.Unlock()
							if !ok {
								resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
								return resp, ss, nil
							}

							packet = rpc.NewCloseResponse(
								ip.Header.CallID,
								smb2.STATUS_OK,
							)
						}
					}

				case "srvsvc":
					switch body.OpNum {
					case rpc.NET_SHARE_GET_INFO:
						var request rpc.NetShareGetInfoRequest
						request.Unmarshal(ip.Payload)
						if request.Level == 1 {
							packet = rpc.NewNetShareGetInfo1Response(
								ip.Header.CallID,
								request.Share,
								smb2.STATUS_OK,
							)
						}
					}

				case "mdssvc":
					switch body.OpNum {
					case rpc.MDS_OPEN:
						var request rpc.MdsOpenRequest
						request.Unmarshal(ip.Payload)
						packet = rpc.NewMdsOpenResponse(
							ip.Header.CallID,
							request,
							"",
							smb2.STATUS_OK,
						)
					}
				}
			}

			var buf bytes.Buffer
			packet.Write(&buf)
			resp := &smb2.IoctlResponse{}
			resp.FromRequest(ir)
			resp.Generate(ir.CtlCode(), id, 0, buf.Bytes())
			return resp, ss, nil

		default:
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

	case smb2.SMB2_ECHO:
		er := smb2.EchoRequest{Request: *req}
		if err := er.Validate(); err != nil {
			log.Println("Invalid SMB2_ECHO request:", err)
			return nil, nil, err
		}

		var ss *session
		var found bool
		if er.Header().SessionID() != 0 || er.Header().IsFlagSet(smb2.FLAGS_SIGNED) {
			c.mu.Lock()
			ss, found = c.sessionTable[er.Header().SessionID()]
			c.mu.Unlock()

			if !found {
				resp := smb2.NewErrorResponse(er, smb2.STATUS_USER_SESSION_DELETED, nil)
				return resp, nil, nil
			}

			ss.idleTime = time.Now()
		}

		resp := &smb2.EchoResponse{}
		resp.FromRequest(er)

		return resp, ss, nil

	case smb2.SMB2_QUERY_DIRECTORY:
		qdr := smb2.QueryDirectoryRequest{Request: *req}
		if err := qdr.Validate(); err != nil {
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			log.Println("Invalid SMB2_QUERY_DIRECTORY request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[qdr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(qdr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		if qdr.FileInformationClass() != smb2.FILE_ID_BOTH_DIRECTORY_INFORMATION {
			resp := smb2.NewErrorResponse(qdr, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

		ss.mu.Lock()
		tc, found := ss.treeConnectTable[qdr.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		ss.idleTime = time.Now()
		if qdr.OutputBufferLength() > uint32(c.maxTransactSize) {
			resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		var op *open
		id := qdr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
			resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		if op.grantedAccess&smb2.FILE_LIST_DIRECTORY == 0 {
			resp := smb2.NewErrorResponse(qdr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		req.SetOpenID(id)
		searchPath := qdr.FileName()
		single := qdr.Flags()&smb2.RETURN_SINGLE_ENTRY > 0
		var buf []byte
		if op.lastSearch != "" && op.lastSearch == searchPath && qdr.Flags()&smb2.RESTART_SCANS == 0 {
			if len(op.searchResults) == 0 {
				op.lastSearch = ""
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_NO_MORE_FILES, nil)
				return resp, ss, nil
			}

			var num int
			buf, num = smb2.QueryDirectoryBuffer(op.searchResults, qdr.OutputBufferLength(), single, false, 0, 0, time.Time{}, time.Time{})
			op.searchResults = op.searchResults[num:]
		} else {
			if err := op.queryDirectory(searchPath); err != nil && searchPath != "*" {
				if errors.Is(err, errNoFiles) {
					resp := smb2.NewErrorResponse(qdr, smb2.STATUS_NO_SUCH_FILE, nil)
					return resp, ss, nil
				}

				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, ss, nil
			}

			id, pid, ct, pct, err := tc.share.client.GetParentInfo(op.ctx, tc.share.bucket, searchPath)
			if err != nil {
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_BAD_NETWORK_NAME, nil)
				return resp, ss, nil
			}

			var num int
			buf, num = smb2.QueryDirectoryBuffer(op.searchResults, qdr.OutputBufferLength(), single, qdr.FileName() == "*", id, pid, time.Time(ct), time.Time(pct))
			op.searchResults = op.searchResults[num:]
		}

		resp := &smb2.QueryDirectoryResponse{}
		resp.FromRequest(qdr)
		resp.Generate(buf)

		return resp, ss, nil

	case smb2.SMB2_CHANGE_NOTIFY:
		cnr := smb2.ChangeNotifyRequest{Request: *req}
		if err := cnr.Validate(); err != nil {
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(cnr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			log.Println("Invalid SMB2_CHANGE_NOTIFY request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[cnr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(cnr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.idleTime = time.Now()
		if cnr.OutputBufferLength() > uint32(c.maxTransactSize) {
			resp := smb2.NewErrorResponse(cnr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		var op *open
		id := cnr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(cnr, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
			resp := smb2.NewErrorResponse(cnr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		if op.grantedAccess&smb2.FILE_LIST_DIRECTORY == 0 {
			resp := smb2.NewErrorResponse(cnr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		req.SetOpenID(id)
		aid := make([]byte, 8)
		rand.Read(aid)
		asyncID := binary.LittleEndian.Uint64(aid)
		req.Header().SetAsyncID(asyncID)
		req.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
		c.mu.Lock()
		c.asyncCommandList[asyncID] = req
		ch := make(chan struct{})
		c.stopChans[req.CancelRequestID()] = ch
		c.mu.Unlock()

		go op.checkForChanges(cnr, ch)

		resp := smb2.NewErrorResponse(cnr, smb2.STATUS_PENDING, nil)
		resp.Header().SetAsyncID(asyncID)
		resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
		resp.Header().ClearFlag(smb2.FLAGS_RELATED_OPERATIONS)
		resp.Header().ClearFlag(smb2.FLAGS_SIGNED)
		resp.Header()[len(resp.Header())-1] = 0x21

		return resp, ss, nil

	case smb2.SMB2_QUERY_INFO:
		qir := smb2.QueryInfoRequest{Request: *req}
		if err := qir.Validate(); err != nil {
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(qir, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			log.Println("Invalid SMB2_QUERY_INFO request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[qir.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(qir, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		tc, found := ss.treeConnectTable[qir.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(qir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		ss.idleTime = time.Now()
		if qir.OutputBufferLength() > uint32(c.maxTransactSize) {
			resp := smb2.NewErrorResponse(qir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		var op *open
		id := qir.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(qir, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		req.SetOpenID(id)

		var info []byte
		switch qir.InfoType() {
		case smb2.INFO_FILE:
			switch qir.FileInfoClass() {
			case smb2.FileAllInformation:
				info = op.fileAllInformation()
			case smb2.FileStandardInformation:
				info = op.fileStandardInformation()
			case smb2.FileNetworkOpenInformation:
				info = op.fileNetworkOpenInformation()
			default:
				resp := smb2.NewErrorResponse(qir, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			}
		case smb2.INFO_FILESYSTEM:
			switch qir.FileInfoClass() {
			case smb2.FileFsVolumeInformation:
				info = smb2.FileFsVolumeInfo(tc.share.createdAt, tc.share.serialNo(), tc.share.name)
			case smb2.FileFsAttributeInformation:
				info = smb2.FileFsAttributeInfo()
			case smb2.FileFsSizeInformation:
				rs, err := tc.share.client.RemainingStorage(op.ctx)
				if err != nil {
					log.Println("Error calculating remaining storage:", err)
				} else {
					us, err := tc.share.client.UsedStorage(op.ctx, tc.share.bucket)
					if err != nil {
						log.Println("Error calculating used storage:", err)
					} else {
						red, err := tc.share.client.Redundancy(op.ctx)
						if err != nil {
							log.Println("Error getting redundancy settings:", err)
						} else {
							info = smb2.FileFsSizeInfo(rs+us, us, red)
						}
					}
				}
			case smb2.FileFsFullSizeInformation:
				rs, err := tc.share.client.RemainingStorage(op.ctx)
				if err != nil {
					log.Println("Error calculating remaining storage:", err)
				} else {
					us, err := tc.share.client.UsedStorage(op.ctx, tc.share.bucket)
					if err != nil {
						log.Println("Error calculating used storage:", err)
					} else {
						red, err := tc.share.client.Redundancy(op.ctx)
						if err != nil {
							log.Println("Error getting redundancy settings:", err)
						} else {
							info = smb2.FileFsFullSizeInfo(rs+us, us, red)
						}
					}
				}
			default:
				resp := smb2.NewErrorResponse(qir, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			}

		case smb2.INFO_SECURITY:
			info = smb2.NewSecInfo(ss.securityContext, qir.AdditionalInformation(), op.grantedAccess)

		default:
			resp := smb2.NewErrorResponse(qir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

		resp := &smb2.QueryInfoResponse{}
		resp.FromRequest(qir)
		resp.Generate(info)
		return resp, ss, nil

	case smb2.SMB2_SET_INFO:
		sir := smb2.SetInfoRequest{Request: *req}
		if err := sir.Validate(); err != nil {
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(sir, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			log.Println("Invalid SMB2_SET_INFO request:", err)
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[sir.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(sir, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		ss.mu.Lock()
		tc, found := ss.treeConnectTable[sir.Header().TreeID()]
		ss.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(sir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		ss.idleTime = time.Now()
		if len(sir.Buffer()) == 0 || uint64(len(sir.Buffer())) > c.maxTransactSize {
			resp := smb2.NewErrorResponse(sir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		var op *open
		id := sir.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if !found || op.durableFileID != dfid {
			if req.GroupID() > 0 {
				op = c.findOpen(req.GroupID())
			}

			if op == nil {
				resp := smb2.NewErrorResponse(sir, smb2.STATUS_FILE_CLOSED, nil)
				return resp, ss, nil
			}

			id = op.id()
		}

		req.SetOpenID(id)
		switch sir.InfoType() {
		case smb2.INFO_FILE:
			switch sir.FileInfoClass() {
			case smb2.FileEndOfFileInformation:
				if op.grantedAccess&smb2.FILE_WRITE_DATA == 0 {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_ACCESS_DENIED, nil)
					return resp, ss, nil
				}

				size := binary.LittleEndian.Uint64(sir.Buffer())
				if op.pendingUpload != nil {
					eTag, err := tc.share.client.FinishUpload(
						op.ctx,
						tc.share.bucket,
						op.pathName,
						op.pendingUpload.uploadID,
						op.pendingUpload.parts,
					)
					if err != nil {
						log.Println("Error completing write:", err)
						resp := smb2.NewErrorResponse(sir, smb2.STATUS_DATA_ERROR, nil)
						return resp, ss, nil
					} else {
						op.pendingUpload = nil
						buf, err := hex.DecodeString(eTag)
						if err == nil && len(buf) >= 8 {
							op.handle = binary.LittleEndian.Uint64(buf[:8])
						}
					}

					op.size = size
					op.allocated = size
				}

			case smb2.FileBasicInformation:
				if op.grantedAccess&smb2.FILE_WRITE_ATTRIBUTES == 0 {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_ACCESS_DENIED, nil)
					return resp, ss, nil
				}

				var fbi smb2.FileBasicInfo
				if err := fbi.Decode(sir.Buffer()); err != nil {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_INVALID_PARAMETER, nil)
					return resp, ss, nil
				}

				var modTime time.Time
				if !fbi.CreationTime.IsZero() {
					modTime = fbi.CreationTime
				}

				if !fbi.LastWriteTime.IsZero() && fbi.LastWriteTime.After(modTime) {
					modTime = fbi.LastWriteTime
				}

				if !fbi.ChangeTime.IsZero() && fbi.ChangeTime.After(modTime) {
					modTime = fbi.ChangeTime
				}

				if modTime.After(op.lastModified) {
					op.lastModified = modTime
				}

				if fbi.FileAttributes != 0 {
					op.fileAttributes = fbi.FileAttributes
				}

			case smb2.FileDispositionInformation:
				if op.grantedAccess&smb2.DELETE == 0 {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_ACCESS_DENIED, nil)
					return resp, ss, nil
				}

				if sir.Buffer()[0] == 1 {
					op.createOptions |= smb2.FILE_DELETE_ON_CLOSE
				}

			case smb2.FileRenameInformation:
				if op.grantedAccess&smb2.DELETE == 0 {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_ACCESS_DENIED, nil)
					return resp, ss, nil
				}

				var fri smb2.FileRenameInfo
				if err := fri.Decode(sir.Buffer()); err != nil {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_INFO_LENGTH_MISMATCH, nil)
					return resp, ss, nil
				}

				if fri.RootDirectory != 0 {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_INVALID_PARAMETER, nil)
					return resp, ss, nil
				}

				if err := tc.share.client.RenameObject(
					op.ctx,
					tc.share.bucket,
					op.pathName,
					fri.FileName,
					op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY > 0,
					fri.ReplaceIfExists,
				); err != nil {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_OBJECT_NAME_COLLISION, nil)
					return resp, ss, nil
				}

			default:
				resp := smb2.NewErrorResponse(sir, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			}

		default:
			resp := smb2.NewErrorResponse(sir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

		resp := &smb2.SetInfoResponse{}
		resp.FromRequest(sir)
		return resp, ss, nil

	default:
		log.Println("Unrecognized command:", req.Header().Command())
		return nil, nil, errors.New("unrecognized command")
	}
}

func (c *connection) processRequests() {
	for {
		var req *smb2.Request
		c.mu.Lock()
		if len(c.requestList) > 0 {
			_, req = utils.FindMinKey(c.requestList)
		}
		c.mu.Unlock()

		if req != nil {
			resp, ss, err := c.processRequest(req)
			if err != nil {
				c.server.closeConnection(c)
				return
			}

			c.mu.Lock()
			delete(c.requestList, resp.Header().MessageID())
			var pendingResp smb2.GenericResponse
			if resp.GroupID() > 0 {
				pendingResp = c.pendingResponses[resp.GroupID()]
			}
			c.mu.Unlock()

			if resp.Header().Command() == smb2.SMB2_CHANGE_NOTIFY {
				if pendingResp != nil && req.Header().NextCommand() == 0 {
					pendingResp.Header().SetCreditResponse(1)
					c.server.writeResponse(c, ss, pendingResp)
					c.mu.Lock()
					delete(c.pendingResponses, resp.GroupID())
					c.mu.Unlock()
				}
				c.server.writeResponse(c, ss, resp)
			} else if pendingResp != nil {
				pendingResp.Append(resp)
				if req.Header().NextCommand() == 0 {
					c.server.writeResponse(c, ss, pendingResp)
					c.mu.Lock()
					delete(c.pendingResponses, resp.GroupID())
					c.mu.Unlock()
				}
			} else if resp.GroupID() == 0 || req.Header().NextCommand() == 0 {
				c.server.writeResponse(c, ss, resp)
			} else {
				c.mu.Lock()
				resp.SetSessionID(resp.Header().SessionID())
				resp.SetTreeID(resp.Header().TreeID())
				c.pendingResponses[resp.GroupID()] = resp
				c.mu.Unlock()
			}
		}

		select {
		case <-c.closeChan:
			return
		default:
		}
	}
}

func (c *connection) sendResponses() {
	for {
		select {
		case <-c.closeChan:
			return
		case msg := <-c.writeChan:
			err := writeMessage(c.conn, msg)
			if err != nil {
				log.Println("Error sending message:", err)
				c.server.closeConnection(c)
			}
		}
	}
}

func (c *connection) findOpen(groupID uint64) *open {
	c.mu.Lock()
	resp, found := c.pendingResponses[groupID]
	c.mu.Unlock()
	if !found {
		return nil
	}

	id := resp.OpenID()
	if id == nil {
		return nil
	}

	dfid := binary.LittleEndian.Uint64(id[8:16])
	c.server.mu.Lock()
	op := c.server.globalOpenTable[dfid]
	c.server.mu.Unlock()

	return op
}

func (c *connection) cancelRequest(req *smb2.Request) error {
	cr := smb2.CancelRequest{Request: *req}
	if err := cr.Validate(); err != nil {
		return err
	}

	var ss *session
	var found bool
	if cr.Header().IsFlagSet(smb2.FLAGS_SIGNED) {
		ss, found = c.sessionTable[cr.Header().SessionID()]
		if !found {
			return errSessionNotFound
		}

		if !ss.validateRequest(req) {
			return errInvalidSignature
		}
	}

	var target *smb2.Request
	if cr.Header().IsFlagSet(smb2.FLAGS_ASYNC_COMMAND) {
		target, found = c.asyncCommandList[cr.Header().AsyncID()]
	} else {
		target, found = c.requestList[cr.Header().MessageID()]
	}

	if !found {
		return nil
	}

	if target.Header().Command() == smb2.SMB2_WRITE {
		wr := smb2.WriteRequest{Request: *target}
		var op *open
		id := wr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		ss.mu.Lock()
		op, found = ss.openTable[fid]
		ss.mu.Unlock()
		if found && op.durableFileID == dfid && op.pendingUpload != nil {
			tc := op.treeConnect
			if err := tc.share.client.AbortUpload(op.ctx, tc.share.bucket, op.pathName, op.pendingUpload.uploadID); err != nil {
				log.Println("Couldn't abort upload:", err)
			} else {
				op.pendingUpload = nil
			}
		}
	}

	resp := smb2.NewErrorResponse(target, smb2.STATUS_CANCELLED, nil)
	resp.Header().ClearFlag(smb2.FLAGS_RELATED_OPERATIONS)
	if cr.Header().IsFlagSet(smb2.FLAGS_ASYNC_COMMAND) {
		resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
		resp.Header().SetCreditResponse(0)
		resp.Header().SetAsyncID(cr.Header().AsyncID())
	}

	c.server.writeResponse(c, ss, resp)

	if cr.Header().IsFlagSet(smb2.FLAGS_ASYNC_COMMAND) {
		delete(c.asyncCommandList, cr.Header().AsyncID())
	} else {
		delete(c.requestList, cr.Header().MessageID())
	}

	ch, ok := c.stopChans[target.CancelRequestID()]
	if ok {
		close(ch)
		delete(c.stopChans, target.CancelRequestID())
	}

	return nil
}
