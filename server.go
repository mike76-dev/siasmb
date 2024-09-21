package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mike76-dev/siasmb/smb2"
)

type serverStats struct {
	start  time.Time
	fOpens uint32
	// devOpens uint32
	// jobsQueued uint32
	sOpens    uint32
	sTimedOut uint32
	// sErrorOut uint32
	// pwErrors uint32
	permErrors uint32
	// sysErrors uint32
	bytesSent uint64
	bytesRcvd uint64
	// avResponse time.Time
	// reqBufNeed uint32
	// bigBufNeed uint32
}

type server struct {
	enabled bool
	stats   serverStats
	// shareList
	// globalOpenTable
	globalSessionTable              map[uint64]*session
	connectionList                  map[string]*connection
	serverGuid                      [16]byte
	isDfsCapable                    bool
	serverSideCopyMaxNumberOfChunks uint64
	serverSideCopyMaxChunkSize      uint64
	serverSideCopyMaxDataSize       uint64
	// serverHashLevel: 2.1+
	// globalLeaseTableList: 2.1+ & leasing
	// maxResiliencyTimeout: 2.1+ & resiliency
	// resilientOpenScavengerExpiryTime: 2.1+ & resiliency
	// globalClientTable: 3.x
	// encryptData: 3.x
	// rejectUnencryptedAccess: 3.x
	// isMultiChannelCapable: 3.x
	// allowAnonymousAccess: 3.x
	// isSharedVHDSupported: 3.0.2+
	// maxClusterDialect: 3.1.1
	// supportsTreeConnectExtn: 3.1.1
	// allowNamedPipeAccessOverQUIC: 3.1.1
	// isMutualAuthOverQUICSupported: 3.1.1
	// serverCertificateMappingTable: 3.1.1
	listener net.Listener
	mu       sync.Mutex
}

type response interface {
	Encode([]byte) error
	EncodedLength() int
	GetHeader() smb2.Header
}

func newServer(l net.Listener) *server {
	s := &server{
		enabled:                         true,
		serverGuid:                      uuid.New(),
		serverSideCopyMaxNumberOfChunks: 256,
		serverSideCopyMaxChunkSize:      2 >> 10, // 1MiB
		serverSideCopyMaxDataSize:       2 >> 14, // 16MiB
		connectionList:                  make(map[string]*connection),
		globalSessionTable:              make(map[uint64]*session),
		listener:                        l,
	}
	s.stats.start = time.Now()
	return s
}

func (s *server) newConnection(conn net.Conn) *connection {
	c := &connection{
		commandSequenceWindow: make(map[uint64]struct{}),
		requestList:           make(map[uint64]smb2.Request),
		asyncCommandList:      make(map[uint64]smb2.Request),
		sessionTable:          make(map[uint64]*session),
		conn:                  conn,
		negotiateDialect:      smb2.SMB_DIALECT_UNKNOWN,
		dialect:               "Unknown",
		clientName:            conn.RemoteAddr().String(),
		creationTime:          time.Now(),
		maxTransactSize:       smb2.MaxTransactSize,
		maxReadSize:           smb2.MaxReadSize,
		maxWriteSize:          smb2.MaxWriteSize,
	}

	c.mu.Lock()
	c.commandSequenceWindow[0] = struct{}{}
	c.mu.Unlock()

	s.mu.Lock()
	s.connectionList[c.clientName] = c
	s.mu.Unlock()

	return c
}

func (s *server) closeConnection(c *connection) {
	s.mu.Lock()
	delete(s.connectionList, c.clientName)
	s.mu.Unlock()
	c.conn.Close()
}

func (s *server) writeResponse(c *connection, resp response) error {
	buf := make([]byte, resp.EncodedLength())
	if err := resp.Encode(buf); err != nil {
		return err
	}
	fmt.Println("Encoded response:", buf) //TODO

	if err := writeMessage(c.conn, buf); err != nil {
		return err
	}

	c.mu.Lock()
	delete(c.requestList, resp.GetHeader().MessageID)
	s.stats.bytesSent += uint64(len(buf))
	c.mu.Unlock()

	return nil
}
