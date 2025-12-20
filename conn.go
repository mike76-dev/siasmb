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
	"go.sia.tech/renterd/v2/api"
)

const (
	// staleThreshold is how soon a connection or a session are considered stale.
	staleThreshold = 10 * time.Minute
)

var (
	errRequestNotWithinWindow        = errors.New("request out of command sequence window")
	errCommandSecuenceWindowExceeded = errors.New("command sequence window exceeded")
	errLongRequest                   = errors.New("request too long")
	errAlreadyNegotiated             = errors.New("dialect already negotiated")
	errInvalidSignature              = errors.New("invalid signature")
)

// connection represents a Connection object.
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
	clientGuid            []byte
	maxTransactSize       uint64
	maxWriteSize          uint64
	maxReadSize           uint64
	supportsMultiCredit   bool
	sessionTable          map[uint64]*session
	creationTime          time.Time

	// Auxiliary fields.
	conn       net.Conn
	mu         sync.Mutex
	server     *server
	ntlmServer *ntlm.Server
	writeChan  chan []byte
	closeChan  chan struct{}
	once       sync.Once
	stopChans  map[uint64]chan struct{}
}

// grantCredits increases the number of credits available to the client by the given number.
// Each SMB2 request consumes at least one credit.
func (c *connection) grantCredits(mid uint64, numCredits uint16) error {
	// Find the maximal message ID that a request may come in with.
	max, _ := utils.FindMaxKey(c.commandSequenceWindow)
	if max == 0 { // Window empty or only containing zero
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

// acceptRequest processes an SMB message into one or more requests and puts them in the queue.
func (c *connection) acceptRequest(msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if uint64(len(msg)) > c.maxTransactSize+256 {
		return errLongRequest
	}

	// Assign a random cancel ID.
	cid := make([]byte, 8)
	rand.Read(cid)

	reqs, err := smb2.GetRequests(msg, binary.LittleEndian.Uint64(cid))
	if err != nil {
		return err
	}

	var ss *session
	var found bool
	for i, req := range reqs {
		if err := req.Header().Validate(); err != nil {
			return err
		}

		var mid uint64
		if req.Header().IsSmb() {
			// Once an SMB2 dialect has been negotiated, no more legacy SMB requests are allowed.
			// The protocol explicitly prohibits that; however, many cients do that nevertheless.
			if c.negotiateDialect != smb2.SMB_DIALECT_UNKNOWN || len(reqs) > 1 {
				return smb2.ErrWrongProtocol
			}
			c.grantCredits(mid, 1) // Grant just one credit
		} else {
			mid = req.Header().MessageID()
			credits := req.Header().CreditRequest() // Grant whatever the CreditRequest is
			if credits == 0 {                       // The number of credits cannot be zero
				credits = 1
			}

			c.grantCredits(mid, credits)
			if req.Header().Command() == smb2.SMB2_CANCEL { // SMB2_CANCEL requests are handled separately
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

		// If this is the first request in a chain of related requests, or if the requests are unrelated,
		// find the associated session.
		if i == 0 || req.GroupID() == 0 {
			ss, found = c.sessionTable[req.Header().SessionID()]
		}

		if found && !ss.validateRequest(req) {
			return errInvalidSignature
		}

		// Request processed; this message ID is not allowed anymore.
		delete(c.commandSequenceWindow, mid)

		// Put request in the queue.
		c.requestList[mid] = req
	}

	return nil
}

// processRequest processes the request depending on its Command field and genertates a response.
func (c *connection) processRequest(req *smb2.Request) (smb2.GenericResponse, *session, error) {
	if req.Header().IsSmb() && req.Header().LegacyCommand() == smb2.SMB_COM_NEGOTIATE {
		// The client has sent a legacy SMB_COM_NEGOTIATE request.
		nr := smb2.NegotiateRequest{Request: *req}
		if err := nr.Validate(); err != nil {
			if errors.Is(err, smb2.ErrDialectNotSupported) { // The client doesn't support SMB2, decline
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

		// Respond with an SMB2_NEGOTIATE response.
		dialect := nr.MaxCommonDialect()
		if dialect == smb2.SMB_DIALECT_202 {
			c.negotiateDialect = dialect
			c.dialect = "2.0.2"
		} else if dialect == smb2.SMB_DIALECT_MULTICREDIT {
			c.supportsMultiCredit = true
		}

		resp := smb2.NewNegotiateResponse(c.server.serverGuid[:], c.ntlmServer, dialect)
		return resp, nil, nil
	}

	switch req.Header().Command() {
	case smb2.SMB2_NEGOTIATE:
		if c.negotiateDialect != smb2.SMB_DIALECT_UNKNOWN { // A dialect has already been negotiated
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
		c.clientGuid = nr.ClientGuid()
		c.negotiateDialect = nr.MaxCommonDialect()
		switch c.negotiateDialect {
		case smb2.SMB_DIALECT_202:
			c.dialect = "2.0.2"
		case smb2.SMB_DIALECT_21:
			c.dialect = "2.1"
		case smb2.SMB_DIALECT_30:
			c.dialect = "3.0"
		case smb2.SMB_DIALECT_302:
			c.dialect = "3.0.2"
		case smb2.SMB_DIALECT_311:
			c.dialect = "3.1.1"
		}

		if nr.SecurityMode()&smb2.NEGOTIATE_SIGNING_REQUIRED > 0 {
			c.shouldSign = true
		}

		if c.negotiateDialect != smb2.SMB_DIALECT_202 {
			c.supportsMultiCredit = true
		}

		resp := &smb2.NegotiateResponse{}
		resp.FromRequest(nr)
		resp.Generate(c.server.serverGuid[:], c.ntlmServer, c.negotiateDialect)

		return resp, nil, nil

	case smb2.SMB2_SESSION_SETUP:
		ssr := smb2.SessionSetupRequest{Request: *req}
		if err := ssr.Validate(); err != nil {
			log.Println("Invalid SMB2_SESSION_SETUP request:", err)
			return nil, nil, err
		}

		// Find a session or create a new one.
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
		if found { // Session found, proceed to the step 2
			authToken, err := spnego.DecodeNegTokenResp(ssr.SecurityBuffer())
			if err != nil { // It's possible that the token is not wrapped in SPNEGO; fall back to raw bytes
				authToken = &spnego.NegTokenResp{ResponseToken: ssr.SecurityBuffer()}
			}

			// Try to authenticate the user.
			// This code doesn't distinguish between different authentication errors; perhaps it should.
			if err := c.ntlmServer.Authenticate(authToken.ResponseToken); err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				c.server.mu.Lock()
				c.server.stats.pwErrors++
				c.server.mu.Unlock()
				resp := smb2.NewErrorResponse(ssr, smb2.STATUS_NO_SUCH_USER, nil)
				return resp, nil, nil
			}

			// User successfully authenticated.
			ss.finalize(ssr)
			ss.idleTime = time.Now()
			token = spnego.FinalNegTokenResp
		} else { // Begin the session setup process
			negToken, err := spnego.DecodeNegTokenInit(ssr.SecurityBuffer())
			var noSpnego bool
			if err != nil { // It's possible that the token is not wrapped in SPNEGO; fall back to raw bytes
				negToken = &spnego.NegTokenInit{MechToken: ssr.SecurityBuffer()}
				noSpnego = true
			}

			// Generate a challenge.
			challenge, err := c.ntlmServer.Challenge(negToken.MechToken)
			if err != nil {
				c.server.deregisterSession(c, ss.sessionID)
				log.Println("Couldn't generate CHALLENGE:", err)
				return nil, nil, err
			}

			if noSpnego {
				token = challenge
			} else {
				token, err = spnego.EncodeNegTokenResp(0x01, spnego.NlmpOid, challenge, nil)
				if err != nil {
					c.server.deregisterSession(c, ss.sessionID)
					log.Println("Couldn't generate CHALLENGE token:", err)
					return nil, nil, err
				}
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
			resp.Header().SetCreditResponse(1) // Only one credit if the process is incomplete
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
		if tc.share.name == "ipc$" { // A named pipe is being created
			switch strings.ToLower(path) {
			case "srvsvc", "lsarpc", "mdssvc":
				info = api.ObjectMetadata{
					Bucket: tc.share.bucket,
					Key:    path,
				}
				result = smb2.FILE_OPENED
			default: // Other named pipes are not supported
				cancel()
				c.server.mu.Lock()
				c.server.stats.permErrors++
				c.server.mu.Unlock()
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_ACCESS_DENIED, nil)
				return resp, ss, nil
			}
		} else {
			access := grantAccess(cr, tc, ss)
			if !access { // The user has insufficient access rights
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
						info = api.ObjectMetadata{
							Bucket:  tc.share.bucket,
							Key:     "/" + path,
							ModTime: api.TimeRFC3339(time.Now()),
						}
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
					info = api.ObjectMetadata{
						Bucket:  tc.share.bucket,
						Key:     "/" + path,
						ModTime: api.TimeRFC3339(time.Now()),
					}
					result = smb2.FILE_CREATED
					if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE > 0 { // Make a new directory
						info.Key += "/"
						if err := tc.share.client.MakeDirectory(ctx, tc.share.bucket, path); err != nil {
							cancel()
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
						info = api.ObjectMetadata{
							Bucket:  tc.share.bucket,
							Key:     "/" + path,
							ModTime: api.TimeRFC3339(time.Now()),
						}
						result = smb2.FILE_CREATED
						if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE > 0 { // Make a new directory
							info.Key += "/"
							if err := tc.share.client.MakeDirectory(ctx, tc.share.bucket, path); err != nil {
								cancel()
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
						info = api.ObjectMetadata{
							Bucket:  tc.share.bucket,
							Key:     "/" + path,
							ModTime: api.TimeRFC3339(time.Now()),
						}
						result = smb2.FILE_CREATED
						if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE > 0 { // Make a new directory
							info.Key += "/"
							if err := tc.share.client.MakeDirectory(ctx, tc.share.bucket, path); err != nil {
								cancel()
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

		if restored { // This file has already been "created", "restore" it
			cancel()
			c.server.restoreOpen(op)
		} else {
			op = ss.registerOpen(cr, tc, info, ctx, cancel)
			if op == nil {
				cancel()
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, ss, nil
			}
		}

		if result == smb2.FILE_CREATED { // Persist the file for any future requests
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
			case smb2.CREATE_EA_BUFFER: // renterd doesn't support extended file attributes, so why should we?
				resp := smb2.NewErrorResponse(cr, smb2.STATUS_EAS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			case smb2.CREATE_QUERY_MAXIMAL_ACCESS_REQUEST:
				respContexts[id] = smb2.HandleCreateQueryMaximalAccessRequest(ctx, op.lastModified, op.grantedAccess)
			case smb2.CREATE_QUERY_ON_DISK_ID:
				respContexts[id] = smb2.HandleCreateQueryOnDiskID(op.handle, tc.share.volumeID)
			case smb2.CREATE_ALLOCATION_SIZE: // The file is about to be uploaded, we just got its size
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
		if op.pendingUpload != nil { // This SMB2_CLOSE request is a sign for us to flush any active multipart upload
			_, err := op.treeConnect.share.client.FinishUpload(
				op.ctx,
				op.treeConnect.share.bucket,
				op.pathName,
				op.pendingUpload.uploadID,
				op.pendingUpload.parts,
			)
			if err != nil {
				log.Println("Error completing write:", err)
			} else {
				op.size = op.pendingUpload.totalSize
				op.allocated = op.pendingUpload.totalSize
				op.pendingUpload = nil
			}
		}

		if op.createOptions&smb2.FILE_DELETE_ON_CLOSE > 0 { // Delete the file or directory
			tc.mu.Lock()
			delete(tc.persistedOpens, op.pathName)
			tc.mu.Unlock()
			if err := tc.share.client.DeleteObject(op.ctx, tc.share.bucket, op.pathName, op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY > 0); err != nil {
				log.Println("Error deleting object:", err)
			}
		}

		tc.mu.Lock()
		_, found = tc.persistedOpens[op.pathName]
		tc.mu.Unlock()
		c.server.closeOpen(op, found)

		// Issue a response to each SMB2_CHANGE_NOTIFY request that the Open is associated with.
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

	case smb2.SMB2_FLUSH: // We don't do anything on an SMB2_FLUSH request, only send a response
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

		if op.grantedAccess&(smb2.FILE_READ_DATA|smb2.GENERIC_READ) == 0 {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		// A special case: some clients use the SRVSVC named pipe for writing requests to it
		// and reading responses from it. Usually, an SMB2_IOCTL request serves this purpose.
		if strings.ToLower(op.fileName) == "srvsvc" {
			if op.srvsvcData != nil {
				ip := rpc.InboundPacket{}
				ip.Read(bytes.NewBuffer(op.srvsvcData))

				var packet *rpc.OutboundPacket
				switch ip.Header.PacketType {
				case rpc.PACKET_TYPE_BIND:
					body := ip.Body.(*rpc.Bind)
					packet = rpc.NewBindAck(ip.Header.CallID, "\\pipe\\srvsvc", body.ContextList)

				case rpc.PACKET_TYPE_REQUEST:
					body := ip.Body.(*rpc.Request)
					switch body.OpNum {
					case rpc.NET_SHARE_ENUM_ALL:
						var request rpc.NetShareEnumAllRequest
						request.Unmarshal(ip.Payload)
						if request.Level == 1 {
							packet = rpc.NewNetShareEnumAllResponse(
								ip.Header.CallID,
								c.server.enumShares(),
								smb2.STATUS_OK,
							)
						}

					default:
					}

				default:
				}

				var buf bytes.Buffer
				packet.Write(&buf)
				resp := &smb2.ReadResponse{}
				resp.FromRequest(rr)
				resp.Generate(buf.Bytes(), rr.Padding())
				op.srvsvcData = nil
				return resp, ss, nil
			}
		}

		if rr.Offset() >= op.size {
			resp := smb2.NewErrorResponse(rr, smb2.STATUS_END_OF_FILE, nil)
			return resp, ss, nil
		}

		// An SMB2_READ request can take long enough, especially on the Sia network, for the client
		// to drop the connection. We send an interim response and process the request asynchronously
		// to prevent that.
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
			data := op.read(rr.Offset(), length)
			if len(data) < int(rr.MinimumCount()) {
				resp = smb2.NewErrorResponse(rr, smb2.STATUS_END_OF_FILE, nil)
			} else {
				resp = &smb2.ReadResponse{}
				resp.FromRequest(rr)
				resp.(*smb2.ReadResponse).Generate(data, rr.Padding())
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
		if op.fileName != "" && op.fileName[0] == '.' { // Ignore SMB2_WRITE requests to any hidden file (whose name starts with a dot)
			resp := &smb2.WriteResponse{}
			resp.FromRequest(wr)
			resp.Generate(uint32(len(wr.Buffer())))
			return resp, ss, nil
		}

		if (length <= op.size && op.grantedAccess&(smb2.FILE_WRITE_DATA|smb2.GENERIC_WRITE) == 0) || op.grantedAccess&(smb2.FILE_APPEND_DATA|smb2.GENERIC_WRITE) == 0 {
			resp := smb2.NewErrorResponse(wr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		// A special case: some clients use the SRVSVC named pipe for writing requests to it
		// and reading responses from it. Usually, an SMB2_IOCTL request serves this purpose.
		if strings.ToLower(op.fileName) == "srvsvc" {
			buf := make([]byte, len(wr.Buffer()))
			copy(buf, wr.Buffer())
			op.mu.Lock()
			op.srvsvcData = buf
			op.mu.Unlock()
			resp := &smb2.WriteResponse{}
			resp.FromRequest(wr)
			resp.Generate(uint32(len(buf)))
			return resp, ss, nil
		}

		// Initiate a multipart upload if it hasn't been done yet.
		if op.pendingUpload == nil {
			id, err := tc.share.client.StartUpload(op.ctx, tc.share.bucket, op.pathName)
			if err != nil {
				resp := smb2.NewErrorResponse(wr, smb2.STATUS_DATA_ERROR, nil)
				return resp, ss, nil
			}

			op.pendingUpload = &upload{uploadID: id}
		}

		// An SMB2_WRITE request can take long enough, especially on the Sia network, for the client
		// to drop the connection. We send an interim response and process the request asynchronously
		// to prevent that.
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
			if op.pendingUpload == nil { // Should not happen
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
					if op.pendingUpload != nil { // Add the part information to the pending upload
						op.pendingUpload.mu.Lock()
						op.pendingUpload.parts = append(op.pendingUpload.parts, api.MultipartCompletedPart{
							PartNumber: count,
							ETag:       eTag,
						})
						op.pendingUpload.totalSize += uint64(len(wr.Buffer()))
						size := op.pendingUpload.totalSize
						op.pendingUpload.mu.Unlock()
						// If we know the file size, and if all parts have been uploaded, flush the upload.
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
							}
						} else {
							// If we don't know the file size, wait 10 minutes, then flush anyway.
							go func(size uint64) {
								<-time.After(10 * time.Minute)
								if op != nil && op.pendingUpload != nil && op.pendingUpload.totalSize == size {
									eTag, err = op.treeConnect.share.client.FinishUpload(
										op.ctx,
										op.treeConnect.share.bucket,
										op.pathName,
										op.pendingUpload.uploadID,
										op.pendingUpload.parts,
									)
									if err != nil {
										log.Println("Error completing write:", err)
									} else {
										op.size = size
										op.allocated = size
										op.pendingUpload = nil
									}
								}
							}(op.pendingUpload.totalSize)
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

	case smb2.SMB2_LOCK: // We don't do anything on an SMB2_LOCK request, only send a response
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
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_FILE_CLOSED, nil) // Mocking the behavior of Samba on Linux
			return resp, ss, nil
		case smb2.FSCTL_DFS_GET_REFERRALS:
			resp := smb2.NewErrorResponse(ir, smb2.STATUS_NOT_FOUND, nil) // Mocking the behavior of Samba on Linux
			return resp, ss, nil
		case smb2.FSCTL_PIPE_TRANSCEIVE:
			if tc.share.name != "ipc$" { // FSCTL_PIPE_TRANSCEIVE is only allowed on the IPC$ share
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
						// Create an LSA frame for future requests.
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
								tc.share.remark,
								smb2.STATUS_OK,
							)
						}

					case rpc.NET_SHARE_ENUM_ALL:
						var request rpc.NetShareEnumAllRequest
						request.Unmarshal(ip.Payload)
						if request.Level == 1 {
							packet = rpc.NewNetShareEnumAllResponse(
								ip.Header.CallID,
								c.server.enumShares(),
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

		case smb2.FSCTL_SRV_REQUEST_RESUME_KEY:
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
			resp := &smb2.IoctlResponse{}
			resp.FromRequest(ir)
			resp.Generate(ir.CtlCode(), id, 0, op.getResumeKey())
			return resp, ss, nil

		case smb2.FSCTL_CREATE_OR_GET_OBJECT_ID:
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
			resp := &smb2.IoctlResponse{}
			resp.FromRequest(ir)
			resp.Generate(ir.CtlCode(), id, 0, op.getObjectID())
			return resp, ss, nil

		default: // Other FSCTL codes are not supported yet
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

		switch qdr.FileInformationClass() {
		case smb2.FILE_BOTH_DIRECTORY_INFORMATION,
			smb2.FILE_DIRECTORY_INFORMATION,
			smb2.FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION,
			smb2.FILE_ID_64_EXTD_DIRECTORY_INFORMATION,
			smb2.FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION,
			smb2.FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION,
			smb2.FILE_ID_BOTH_DIRECTORY_INFORMATION,
			smb2.FILE_ID_EXTD_DIRECTORY_INFORMATION,
			smb2.FILE_ID_FULL_DIRECTORY_INFORMATION:
		default: // Other classes are not supported yet
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

		if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 { // The Open must be a directory
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
			// If the search has already run with the same parameters, and all results have been sent
			// to the client, respond with the status STATUS_NO_MORE_FILES.
			if len(op.searchResults) == 0 {
				op.lastSearch = ""
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_NO_MORE_FILES, nil)
				return resp, ss, nil
			}

			// Send as many search results as the buffer length allows.
			var num int
			buf, num = smb2.QueryDirectoryBuffer(qdr.FileInformationClass(), op.searchResults, qdr.OutputBufferLength(), single, false, smb2.FileInfo{}, smb2.FileInfo{})
			op.searchResults = op.searchResults[num:]
		} else {
			// Run a new search.
			if err := op.queryDirectory(searchPath); err != nil && searchPath != "*" {
				if errors.Is(err, errNoFiles) { // No such file exists
					resp := smb2.NewErrorResponse(qdr, smb2.STATUS_NO_SUCH_FILE, nil)
					return resp, ss, nil
				}

				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_INVALID_PARAMETER, nil)
				return resp, ss, nil
			}

			dir, parentDir, err := tc.share.client.GetParentInfo(op.ctx, tc.share.bucket, searchPath)
			if err != nil {
				resp := smb2.NewErrorResponse(qdr, smb2.STATUS_BAD_NETWORK_NAME, nil)
				return resp, ss, nil
			}

			// Send as many search results as the buffer length allows.
			var num int
			buf, num = smb2.QueryDirectoryBuffer(qdr.FileInformationClass(), op.searchResults, qdr.OutputBufferLength(), single, qdr.FileName() == "*", dir, parentDir)
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

		if op.fileAttributes&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 { // The Open must be a directory
			resp := smb2.NewErrorResponse(cnr, smb2.STATUS_INVALID_PARAMETER, nil)
			return resp, ss, nil
		}

		if op.grantedAccess&smb2.FILE_LIST_DIRECTORY == 0 {
			resp := smb2.NewErrorResponse(cnr, smb2.STATUS_ACCESS_DENIED, nil)
			return resp, ss, nil
		}

		// Put the request in the async command list.
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

		// Start a thread to monitor the directory for changes.
		go op.checkForChanges(cnr, ch)

		// Send an interim response.
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
			case smb2.FileStreamInformation:
				info = op.fileStreamInformation()
			default: // Other classes are not supported yet
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
				// To estimate the available storage on the Sia network is quite tricky.
				// The workaround is to calculate the total remaining storage of all hosts
				// that renterd has formed contracts with and give it as the available storage.
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
				// Same as above.
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
			case smb2.FileFsDeviceInformation:
				info = smb2.FileFsDeviceInfo()
			case smb2.FileFsObjectIdInformation:
				info = smb2.FileFsObjectIDInfo(tc.share.volumeID)
			default: // Other classes are not supported yet
				resp := smb2.NewErrorResponse(qir, smb2.STATUS_NOT_SUPPORTED, nil)
				return resp, ss, nil
			}

		case smb2.INFO_SECURITY:
			info = smb2.NewSecInfo(ss.securityContext, qir.AdditionalInformation(), op.grantedAccess)

		default: // Other info types are not supported yet
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

				// Some clients set the EoF position of the file to indicate that it has been uploaded.
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

				// Some clients modify the FileBasicInfo to indicate that the file has been uploaded.
				if op.pendingUpload != nil {
					size := op.pendingUpload.totalSize
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

			case smb2.FileDispositionInformation:
				if op.grantedAccess&smb2.DELETE == 0 {
					resp := smb2.NewErrorResponse(sir, smb2.STATUS_ACCESS_DENIED, nil)
					return resp, ss, nil
				}

				if sir.Buffer()[0] == 1 { // Set the delete flag
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

				// Rename the file or the directory.
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

	default: // Other commands are not supported yet
		log.Println("Unrecognized command:", req.Header().Command())
		return nil, nil, errors.New("unrecognized command")
	}
}

// processRequests pulls requests from the queue one by one and submits them for processing.
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
			if resp.GroupID() > 0 { // This response is a part of a chain, pull the chain
				pendingResp = c.pendingResponses[resp.GroupID()]
			}
			c.mu.Unlock()

			if resp.Header().Command() == smb2.SMB2_CHANGE_NOTIFY { // Send the chain if it's complete, then the response
				if pendingResp != nil && req.Header().NextCommand() == 0 {
					pendingResp.Header().SetCreditResponse(1)
					c.server.writeResponse(c, ss, pendingResp)
					c.mu.Lock()
					delete(c.pendingResponses, resp.GroupID())
					c.mu.Unlock()
				}
				c.server.writeResponse(c, ss, resp)
			} else if pendingResp != nil { // Add the response to the chain, then send the chain if it's complete
				pendingResp.Append(resp)
				if req.Header().NextCommand() == 0 {
					c.server.writeResponse(c, ss, pendingResp)
					c.mu.Lock()
					delete(c.pendingResponses, resp.GroupID())
					c.mu.Unlock()
				}
			} else if resp.GroupID() == 0 || req.Header().NextCommand() == 0 { // A standalone response, send it
				c.server.writeResponse(c, ss, resp)
			} else { // Start the response chain
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

// sendResponses takes an SMB message from the sending queue and writes it to the underlying TCP connection.
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

// findOpen finds an Open by the group ID of the response.
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

// cancelRequest cancels a pending asynchronous request.
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

	// The provided request is an SMB2_CANCEL request; we need to find the target request.
	var target *smb2.Request
	if cr.Header().IsFlagSet(smb2.FLAGS_ASYNC_COMMAND) {
		target, found = c.asyncCommandList[cr.Header().AsyncID()]
	} else {
		target, found = c.requestList[cr.Header().MessageID()]
	}

	if !found {
		return nil
	}

	// If we are cancelling an SMB2_WRITE request, we should abort the upload.
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

// isStale returns true if the connection hasn't been used for a certain amount of time.
// This is done to drop unused connections.
func (c *connection) isStale() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If there are no sessions on the connection, check the connection's creation time.
	if len(c.sessionTable) == 0 && time.Since(c.creationTime) > staleThreshold {
		return true
	}

	// Check each individual session: if at least one session is being used, the connection is alive.
	for _, ss := range c.sessionTable {
		if time.Since(ss.idleTime) <= staleThreshold {
			return false
		}
	}

	return true
}
