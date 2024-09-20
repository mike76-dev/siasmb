package smb2

const (
	// SMB2 protocol ID
	PROTOCOL_ID = 0x424d53fe
)

const (
	// Command codes
	SMB2_NEGOTIATE                     = 0x0000
	SMB2_SESSION_SETUP                 = 0x0001
	SMB2_LOGOFF                        = 0x0002
	SMB2_TREE_CONNECT                  = 0x0003
	SMB2_TREE_DISCONNECT               = 0x0004
	SMB2_CREATE                        = 0x0005
	SMB2_CLOSE                         = 0x0006
	SMB2_FLUSH                         = 0x0007
	SMB2_READ                          = 0x0008
	SMB2_WRITE                         = 0x0009
	SMB2_LOCK                          = 0x000a
	SMB2_IOCTL                         = 0x000b
	SMB2_CANCEL                        = 0x000c
	SMB2_ECHO                          = 0x000d
	SMB2_QUERY_DIRECTORY               = 0x000e
	SMB2_CHANGE_NOTIFY                 = 0x000f
	SMB2_QUERY_INFO                    = 0x0010
	SMB2_SET_INFO                      = 0x0011
	SMB2_OPLOCK_BREAK                  = 0x0012
	SMB2_SERVER_TO_CLIENT_NOTIFICATION = 0x0013
)

const (
	// Flags
	SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001
	SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
	SMB2_FLAGS_SIGNED             = 0x00000008
	SMB2_FLAGS_PRIORITY_MASK      = 0x00000070
	SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000
	SMB2_FLAGS_REPLAY_OPERATION   = 0x20000000
)

const (
	// SMB dialects
	SMB_DIALECT_202     = 0x0202
	SMB_DIALECT_21      = 0x0210
	SMB_DIALECT_30      = 0x0300
	SMB_DIALECT_302     = 0x0302
	SMB_DIALECT_311     = 0x0311
	SMB_DIALECT_MULTI   = 0x02ff
	SMB_DIALECT_UNKNOWN = 0xffff
)

const (
	// Security modes
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002
)

const (
	// Capabilities
	SMB2_GLOBAL_CAP_DFS                = 0x00000001
	SMB2_GLOBAL_CAP_LEASING            = 0x00000002
	SMB2_GLOBAL_CAP_LARGE_MTU          = 0x00000004
	SMB2_GLOBAL_CAP_MULTI_CHANNEL      = 0x00000008
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING  = 0x00000020
	SMB2_GLOBAL_CAP_ENCRYPTION         = 0x00000040
	SMB2_GLOBAL_CAP_NOTIFICATIONS      = 0x00000080
)

const (
	// Status codes
	SMB2_STATUS_OK = 0x00000000
)

const (
	// Byte limits
	MaxTransactSize = 1048576 * 2
	MaxReadSize     = 1048576 * 2
	MaxWriteSize    = 1048576 * 2
)
