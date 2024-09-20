package main

import (
	"net"
	"sync"
	"time"

	"github.com/mike76-dev/siasmb/smb2"
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
	// sessionTable
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
