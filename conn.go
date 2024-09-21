package main

import (
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/smb2"
)

var (
	errRequestNotWithinWindow        = errors.New("request out of command sequence window")
	errCommandSecuenceWindowExceeded = errors.New("command sequence window exceeded")
)

type connection struct {
	commandSequenceWindow map[uint64]struct{}
	requestList           map[uint64]smb2.Request
	clientCapabilities    uint32
	negotiateDialect      uint16
	asyncCommandList      map[uint64]smb2.Request
	dialect               string
	shouldSign            bool
	clientName            string
	maxTransactSize       uint64
	maxWriteSize          uint64
	maxReadSize           uint64
	supportsMultiCredit   bool
	// transportName
	sessionTable map[uint64]*session
	creationTime time.Time
	// preauthSessionTable
	// clientGuid: 2.1+
	// serverCapabilities: 3.x
	// clientSecurityMode: 3.x
	// serverSecurityMode: 3.x
	// constrainedConnection: 3.x
	// supportsNotifications: 3.x
	// preauthIntegrityHashId: 3.1.1
	// preauthIntegrityHashValue: 3.1.1
	// cipherId: 3.1.1
	// clientDialects: 3.1.1
	// compressionIds: 3.1.1
	// supportsChainedCompression: 3.1.1
	// rdmaTransformIds: 3.1.1
	// signingAlgorithmId: 3.1.1
	// acceptTransportSecurity: 3.1.1
	// serverCertificateMappingEntry: 3.1.1
	conn net.Conn
	mu   sync.Mutex
}

func (c *connection) receiveRequest(req smb2.Request) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.commandSequenceWindow[req.Header.MessageID]
	if !ok {
		return errRequestNotWithinWindow
	}

	if req.Header.MessageID == math.MaxUint64 {
		return errCommandSecuenceWindowExceeded
	}

	delete(c.commandSequenceWindow, req.Header.MessageID)
	c.commandSequenceWindow[req.Header.MessageID+1] = struct{}{}
	c.requestList[req.Header.MessageID] = req

	return nil
}
