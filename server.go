package main

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mike76-dev/siasmb/rpc"
	"github.com/mike76-dev/siasmb/smb2"
	"github.com/mike76-dev/siasmb/stores"
	"go.sia.tech/core/types"
)

// serverStats keeps track of the server statistics.
type serverStats struct {
	start  time.Time
	fOpens uint32
	// devOpens uint32
	// jobsQueued uint32
	sOpens    uint32
	sTimedOut uint32
	// sErrorOut uint32
	pwErrors   uint32
	permErrors uint32
	// sysErrors uint32
	bytesSent uint64
	bytesRcvd uint64
	// avResponse time.Time
	// reqBufNeed uint32
	// bigBufNeed uint32
}

// Store implements the minimal store.
type Store interface {
	BanHost(host, reason string) error
	GetAccounts(sh stores.Share) (ars []stores.AccessRights, err error)
	GetAccountByID(id int) (acc stores.Account, err error)
	GetShare(id types.Hash256, name string) (s stores.Share, err error)
}

// ServerHashLevel values.
const (
	HashEnableAll = iota
	HashDisableAll
	HashEnableShare
)

var (
	// Supported algorithms.
	supportedHashAlgos        = []uint16{smb2.SHA_512}
	supportedEncryptionAlgos  = []uint16{smb2.AES_128_CCM, smb2.AES_128_GCM}
	supportedCompressionAlgos = []uint16{}
	supportedSigningAlgos     = []uint16{smb2.HMAC_SHA256, smb2.AES_CMAC, smb2.AES_GMAC}
)

// server is the implementation of an SMB server.
type server struct {
	enabled                         bool
	stats                           serverStats
	shareList                       map[string]*share
	globalOpenTable                 map[uint64]*open
	globalSessionTable              map[uint64]*session
	connectionList                  map[string]*connection
	serverGuid                      [16]byte
	isDfsCapable                    bool
	serverSideCopyMaxNumberOfChunks uint64
	serverSideCopyMaxChunkSize      uint64
	serverSideCopyMaxDataSize       uint64
	serverHashLevel                 int
	serverCapabilities              uint32
	globalClientTable               map[[16]byte]*smbClient
	encryptData                     bool
	rejectUnencryptedAccess         bool
	allowAnonymousAccess            bool
	compressionSupported            bool
	chainedCompressionSupported     bool

	// Auxiliary fields.
	listener        net.Listener
	mu              sync.Mutex
	connectionCount map[string]int
	store           Store
	debug           bool
}

// newServer returns an initialized SMB server.
func newServer(l net.Listener, st Store, debug bool) *server {
	s := &server{
		enabled:                         true,
		serverGuid:                      uuid.New(),
		serverSideCopyMaxNumberOfChunks: 256,
		serverSideCopyMaxChunkSize:      2 >> 10, // 1MiB
		serverSideCopyMaxDataSize:       2 >> 14, // 16MiB
		serverHashLevel:                 HashDisableAll,
		shareList:                       make(map[string]*share),
		connectionList:                  make(map[string]*connection),
		globalOpenTable:                 make(map[uint64]*open),
		globalSessionTable:              make(map[uint64]*session),
		globalClientTable:               make(map[[16]byte]*smbClient),
		listener:                        l,
		connectionCount:                 make(map[string]int),
		store:                           st,
		debug:                           debug,
	}
	s.stats.start = time.Now()
	return s
}

// newConnection creates a new Connection object.
func (s *server) newConnection(conn net.Conn) *connection {
	c := &connection{
		commandSequenceWindow: make(map[uint64]struct{}),
		requestList:           make(map[uint64]*smb2.Request),
		asyncCommandList:      make(map[uint64]*smb2.Request),
		pendingResponses:      make(map[uint64]smb2.GenericResponse),
		sessionTable:          make(map[uint64]*session),
		conn:                  conn,
		negotiateDialect:      smb2.SMB_DIALECT_UNKNOWN,
		dialect:               "Unknown",
		clientName:            conn.RemoteAddr().String(),
		creationTime:          time.Now(),
		maxTransactSize:       smb2.MaxTransactSize,
		maxReadSize:           smb2.MaxReadSize,
		maxWriteSize:          smb2.MaxWriteSize,
		serverCapabilities:    s.serverCapabilities,
		serverSecurityMode:    smb2.NEGOTIATE_SIGNING_ENABLED,
		server:                s,
		writeChan:             make(chan []byte),
		closeChan:             make(chan struct{}),
		stopChans:             make(map[uint64]chan struct{}),
	}

	c.mu.Lock()
	c.commandSequenceWindow[0] = struct{}{}
	c.mu.Unlock()

	s.mu.Lock()
	s.connectionList[c.clientName] = c
	s.mu.Unlock()

	go c.sendResponses()
	go c.processRequests()

	return c
}

// closeConnection destroys the Connection object.
func (s *server) closeConnection(c *connection) {
	s.mu.Lock()
	delete(s.connectionList, c.clientName)
	s.mu.Unlock()
	c.conn.Close()
	c.once.Do(func() { close(c.closeChan) })
}

// writeResponse encodes the response and adds it to the sending queue.
func (s *server) writeResponse(c *connection, ss *session, resp smb2.GenericResponse) {
	wipeSignatures := func(msg []byte) {
		var off uint32
		var zero [16]byte
		for {
			next := binary.LittleEndian.Uint32(msg[off+20 : off+24])
			copy(msg[off+48:off+64], zero[:])
			smb2.Header(msg[off:]).ClearFlag(smb2.FLAGS_SIGNED)
			off += next
			if next == 0 {
				return
			}
		}
	}

	buf := resp.Encode()

	if ss != nil && ss.state == sessionValid { // A session exists, sign if required
		if resp.ShouldEncrypt() {
			wipeSignatures(buf)
			buf = ss.encrypt(buf)
		} else if resp.Header().Command() != smb2.SMB2_SESSION_SETUP && ss.encryptData {
			wipeSignatures(buf)
			buf = ss.encrypt(buf)
		} else if resp.Header().Command() == smb2.SMB2_SESSION_SETUP || resp.Header().IsFlagSet(smb2.FLAGS_SIGNED) {
			ss.sign(buf)
		} else { // Otherwise, wipe the signature(s)
			wipeSignatures(buf)
		}
	}

	c.writeChan <- buf

	s.mu.Lock()
	s.stats.bytesSent += uint64(len(buf))
	s.mu.Unlock()
}

// enumShares generates a NetShareInfo Type 1 structure for each available share.
func (s *server) enumShares() []rpc.NetShareInfo1 {
	var shares []rpc.NetShareInfo1
	for _, sh := range s.shareList {
		share := rpc.NetShareInfo1{
			Share:   sh.name,
			Type:    rpc.STYPE_DISKTREE,
			Comment: sh.remark,
		}

		shares = append(shares, share)
	}

	// Add the "imaginary" IPC (Inter-Protocol Communication) share.
	shares = append(shares, rpc.NetShareInfo1{
		Share:   "IPC$",
		Type:    rpc.STYPE_IPC_HIDDEN,
		Comment: "IPC service",
	})

	return shares
}
