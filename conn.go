package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/ntlm"
	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/spnego"
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
	closeChan  chan struct{}
}

func (c *connection) acceptRequest(msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if uint64(len(msg)) > c.maxTransactSize+256 {
		return errLongRequest
	}
	if !c.supportsMultiCredit && uint64(len(msg)) > 68*1024 {
		return errLongRequest
	}

	cid := make([]byte, 8)
	rand.Read(cid)

	req := smb2.NewRequest(msg, binary.LittleEndian.Uint64(cid))
	if err := req.Header().Validate(); err != nil {
		return err
	}

	var mid uint64
	if req.Header().IsSmb() {
		if c.negotiateDialect != smb2.SMB_DIALECT_UNKNOWN {
			return smb2.ErrWrongProtocol
		}
	} else {
		mid = req.Header().MessageID()
	}

	_, ok := c.commandSequenceWindow[mid]
	if !ok {
		return errRequestNotWithinWindow
	}

	if mid == math.MaxUint64 {
		return errCommandSecuenceWindowExceeded
	}

	ss, found := c.sessionTable[req.Header().SessionID()]
	if found && !ss.validateRequest(req) {
		return errInvalidSignature
	}

	delete(c.commandSequenceWindow, mid)
	c.commandSequenceWindow[mid+1] = struct{}{}
	c.requestList[mid] = req

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
			return nil, nil, err
		}

		resp := smb2.NewNegotiateResponse(c.server.serverGuid[:], c.ntlmServer)
		return resp, nil, nil
	}

	switch req.Header().Command() {
	case smb2.SMB2_NEGOTIATE:
		if c.negotiateDialect != smb2.SMB_DIALECT_UNKNOWN {
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
			return nil, nil, err
		}

		ss, found, err := c.server.registerSession(c, ssr)
		if err != nil {
			if errors.Is(err, errSessionNotFound) {
				resp := smb2.NewErrorResponse(ssr, smb2.STATUS_USER_SESSION_DELETED, nil)
				return resp, nil, nil
			} else {
				return nil, nil, err
			}
		}

		var token []byte
		if found {
			authToken, err := spnego.DecodeNegTokenResp(ssr.SecurityBuffer())
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
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
			token = spnego.FinalNegTokenResp
		} else {
			negToken, err := spnego.DecodeNegTokenInit(ssr.SecurityBuffer())
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				return nil, nil, err
			}

			challenge, err := c.ntlmServer.Challenge(negToken.MechToken)
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				return nil, nil, err
			}

			token, err = spnego.EncodeNegTokenResp(0x01, spnego.NlmpOid, challenge, nil)
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
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

		return resp, ss, nil

	case smb2.SMB2_LOGOFF:
		lr := smb2.LogoffRequest{Request: *req}
		if err := lr.Validate(); err != nil {
			return nil, nil, err
		}

		ss, err := c.server.deregisterSession(c, req.Header().SessionID())
		if err != nil {
			if errors.Is(err, errSessionNotFound) {
				resp := smb2.NewErrorResponse(lr, smb2.STATUS_USER_SESSION_DELETED, nil)
				return resp, nil, nil
			} else {
				return nil, nil, err
			}
		}

		resp := &smb2.LogoffResponse{}
		resp.FromRequest(lr)

		return resp, ss, nil

	case smb2.SMB2_TREE_CONNECT:
		tcr := smb2.TreeConnectRequest{Request: *req}
		if err := tcr.Validate(); err != nil {
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[tcr.Header().SessionID()]
		c.mu.Unlock()
		if !found {
			resp := smb2.NewErrorResponse(tcr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		tc, err := c.newTreeConnect(ss, tcr.PathName())
		if err != nil {
			if errors.Is(err, errNoShare) {
				resp := smb2.NewErrorResponse(tcr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			if errors.Is(err, errAccessDenied) {
				resp := smb2.NewErrorResponse(tcr, smb2.STATUS_ACCESS_DENIED, nil)
				return resp, nil, nil
			}
		}

		resp := &smb2.TreeConnectResponse{}
		resp.FromRequest(tcr)
		resp.Generate(tc.treeID, uint8(tc.share.shareType), tc.maximalAccess)

		return resp, ss, nil

	case smb2.SMB2_TREE_DISCONNECT:
		tdr := smb2.TreeDisconnectRequest{Request: *req}
		if err := tdr.Validate(); err != nil {
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[tdr.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(tdr, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		if err := ss.closeTreeConnect(tdr.Header().TreeID()); err != nil {
			resp := smb2.NewErrorResponse(tdr, smb2.STATUS_NETWORK_NAME_DELETED, nil)
			return resp, nil, nil
		}

		resp := &smb2.TreeDisconnectResponse{}
		resp.FromRequest(tdr)

		return resp, ss, nil

	case smb2.SMB2_IOCTL:
		ir := smb2.IoctlRequest{Request: *req}
		if err := ir.Validate(); err != nil {
			if errors.Is(err, smb2.ErrInvalidParameter) {
				resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, nil, nil
			}
			return nil, nil, err
		}

		c.mu.Lock()
		ss, found := c.sessionTable[ir.Header().SessionID()]
		c.mu.Unlock()

		if !found {
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_USER_SESSION_DELETED, nil)
			return resp, nil, nil
		}

		if ir.MaxInputResponse() > uint32(c.maxTransactSize) || ir.MaxOutputResponse() > uint32(c.maxTransactSize) || len(ir.InputBuffer()) > int(c.maxTransactSize) {
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, nil, nil
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
		default:
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

	default:
		log.Println("Unrecognized command:", req.Header().Command())
		return nil, nil, errors.New("unrecognized command")
	}
}

func (c *connection) processRequests() {
	for {
		c.mu.Lock()
		var req *smb2.Request
		for _, req = range c.requestList {
			break
		}
		c.mu.Unlock()

		if req != nil {
			resp, ss, err := c.processRequest(req)
			if err != nil {
				c.server.closeConnection(c)
				return
			}

			if err := c.server.writeResponse(c, ss, resp); err != nil {
				c.server.closeConnection(c)
				return
			}
		} else {
			time.Sleep(time.Second)
		}

		select {
		case <-c.closeChan:
			return
		default:
		}
	}
}
