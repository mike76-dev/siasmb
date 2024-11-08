package main

import (
	"bytes"
	"context"
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
	"github.com/mike76-dev/siasmb/utils"
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
	closeChan  chan struct{}
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
	if !c.supportsMultiCredit && uint64(len(msg)) > 68*1024 {
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
		} else {
			if req.Header().Command() == smb2.SMB2_CANCEL {
				if err := c.cancelRequest(req); err != nil {
					log.Printf("Couldn't cancel request %d:, %v\n", req.Header().Command(), err)
				}

				continue
			}
			mid = req.Header().MessageID()
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

		if tc.share.name == "ipc$" {
			c.server.mu.Lock()
			c.server.stats.permErrors++
			c.server.mu.Unlock()
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_ACCESS_DENIED, nil)
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

		access := grantAccess(cr, tc, ss)
		if !access {
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_ACCESS_DENIED, nil)
			c.server.mu.Lock()
			c.server.stats.permErrors++
			c.server.mu.Unlock()
			return resp, ss, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), openTimeout)

		info, err := tc.share.client.GetObjectInfo(ctx, tc.share.bucket, path)
		if err != nil {
			log.Printf("Error getting object info (bucket: %s, path: %s): %v\n", tc.share.bucket, path, err)
			if errors.Is(err, context.DeadlineExceeded) {
				cancel()
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_IO_TIMEOUT, nil)
				return resp, ss, nil
			}

			cancel()
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_OBJECT_NAME_NOT_FOUND, nil)
			return resp, ss, nil
		}

		op := ss.registerOpen(cr, tc, info, ctx, cancel)
		if op == nil {
			cancel()
			resp := smb2.NewErrorResponse(cr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
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
				respContexts[id] = smb2.HandleCreateQueryOnDiskID(op.durableFileID, tc.share.volumeID)
			}
		}

		resp := &smb2.CreateResponse{}
		resp.FromRequest(cr)
		resp.Generate(
			op.oplockLevel,
			cr.CreateDisposition(),
			op.size,
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

		id := cr.FileID()
		fid := binary.LittleEndian.Uint64(id[:8])
		dfid := binary.LittleEndian.Uint64(id[8:16])
		var op *open
		ss.mu.Lock()
		ss.idleTime = time.Now()
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
			resp := &smb2.ChangeNotifyResponse{}
			resp.FromRequest(r)
			resp.Header().SetStatus(smb2.STATUS_NOTIFY_CLEANUP)
			resp.Header().SetAsyncID(aid)
			if err := c.server.writeResponse(c, ss, resp); err != nil {
				log.Println("Error writing response:", err)
			}
		}

		resp := &smb2.CloseResponse{}
		resp.FromRequest(cr)
		resp.Generate(op.lastModified, op.size, op.fileAttributes)

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
		default:
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

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
			if err := op.queryDirectory(searchPath); err != nil {
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, ss, nil
			}

			id, pid, ct, pct, err := tc.share.client.GetParentInfo(op.ctx, tc.share.bucket, searchPath)
			if err != nil {
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_BAD_NETWORK_NAME, nil)
				return resp, ss, nil
			}

			var num int
			buf, num = smb2.QueryDirectoryBuffer(op.searchResults, qdr.OutputBufferLength(), single, true, id, pid, time.Time(ct), time.Time(pct))
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
		c.mu.Lock()
		c.asyncCommandList[asyncID] = req
		c.mu.Unlock()

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

		switch qir.InfoType() {
		case smb2.INFO_FILESYSTEM:
			switch qir.FileInfoClass() {
			case smb2.FileFsVolumeInformation:
				info := smb2.FileFsVolumeInfo(tc.share.createdAt, tc.share.serialNo(), tc.share.name)
				resp := &smb2.QueryInfoResponse{}
				resp.FromRequest(qir)
				resp.Generate(info)
				return resp, ss, nil
			case smb2.FileFsAttributeInformation:
				info := smb2.FileFsAttributeInfo()
				resp := &smb2.QueryInfoResponse{}
				resp.FromRequest(qir)
				resp.Generate(info)
				return resp, ss, nil
			case smb2.FileFsFullSizeInformation:
				info := smb2.FileFsFullSizeInfo(tc.share.sectorsPerUnit)
				resp := &smb2.QueryInfoResponse{}
				resp.FromRequest(qir)
				resp.Generate(info)
				return resp, ss, nil
			default:
				resp := smb2.NewErrorResponse(qir, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			}
		default:
			resp := smb2.NewErrorResponse(qir, smb2.STATUS_NOT_SUPPORTED, nil)
			return resp, ss, nil
		}

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
				if err := c.server.writeResponse(c, ss, resp); err != nil {
					log.Println("Error writing response:", err)
					c.server.closeConnection(c)
					return
				}
			} else if pendingResp != nil {
				pendingResp.Append(resp)
				if req.Header().NextCommand() == 0 {
					if err := c.server.writeResponse(c, ss, pendingResp); err != nil {
						log.Println("Error writing response:", err)
						c.server.closeConnection(c)
						return
					}
					c.mu.Lock()
					delete(c.pendingResponses, resp.GroupID())
					c.mu.Unlock()
				}
			} else if resp.GroupID() == 0 || req.Header().NextCommand() == 0 {
				if err := c.server.writeResponse(c, ss, resp); err != nil {
					log.Println("Error writing response:", err)
					c.server.closeConnection(c)
					return
				}
			} else {
				c.mu.Lock()
				resp.SetSessionID(resp.Header().SessionID())
				resp.SetTreeID(resp.Header().TreeID())
				c.pendingResponses[resp.GroupID()] = resp
				c.mu.Unlock()
			}
		} else {
			time.Sleep(100 * time.Millisecond)
		}

		select {
		case <-c.closeChan:
			return
		default:
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

	resp := smb2.NewErrorResponse(target, smb2.STATUS_CANCELLED, nil)
	resp.Header().ClearFlag(smb2.FLAGS_RELATED_OPERATIONS)
	if cr.Header().IsFlagSet(smb2.FLAGS_ASYNC_COMMAND) {
		resp.Header().SetFlag(smb2.FLAGS_ASYNC_COMMAND)
		resp.Header().SetCreditResponse(0)
	}

	if err := c.server.writeResponse(c, ss, resp); err != nil {
		return err
	}

	if cr.Header().IsFlagSet(smb2.FLAGS_ASYNC_COMMAND) {
		delete(c.asyncCommandList, cr.Header().AsyncID())
	} else {
		delete(c.requestList, cr.Header().MessageID())
	}

	return nil
}
