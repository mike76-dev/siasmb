package smb

import "errors"

var (
	// Standardized error messages
	ErrWrongStructureLength = errors.New("wrong structure length")
	ErrWrongProtocol        = errors.New("unsupported protocol")
	ErrWrongParameters      = errors.New("wrong parameter list")
	ErrWrongDataLength      = errors.New("data field has a wrong length")
	ErrWrongArgument        = errors.New("wrong data field")
)

const (
	// SMB 1 protocol ID
	PROTOCOL_ID = 0x424d53ff
)

const (
	// SMB command codes
	SMB_COM_CREATE_DIRECTORY       = 0x00
	SMB_COM_DELETE_DIRECTORY       = 0x01
	SMB_COM_OPEN                   = 0x02
	SMB_COM_CREATE                 = 0x03
	SMB_COM_CLOSE                  = 0x04
	SMB_COM_FLUSH                  = 0x05
	SMB_COM_DELETE                 = 0x06
	SMB_COM_RENAME                 = 0x07
	SMB_COM_QUERY_INFORMATION      = 0x08
	SMB_COM_SET_INFORMATION        = 0x09
	SMB_COM_READ                   = 0x0a
	SMB_COM_WRITE                  = 0x0b
	SMB_COM_LOCK_BYTE_RANGE        = 0x0c
	SMB_COM_UNLOCK_BYTE_RANGE      = 0x0d
	SMB_COM_CREATE_TEMPORARY       = 0x0e
	SMB_COM_CREATE_NEW             = 0x0f
	SMB_COM_CHECK_DIRECTORY        = 0x10
	SMB_COM_PROCESS_EXIT           = 0x11
	SMB_COM_SEEK                   = 0x12
	SMB_COM_LOCK_AND_READ          = 0x13
	SMB_COM_WRITE_AND_UNLOCK       = 0x14
	SMB_COM_READ_RAW               = 0x1a
	SMB_COM_READ_MPX               = 0x1b
	SMB_COM_READ_MPX_SECONDARY     = 0x1c
	SMB_COM_WRITE_RAW              = 0x1d
	SMB_COM_WRITE_MPX              = 0x1e
	SMB_COM_WRITE_MPX_SECONDARY    = 0x1f
	SMB_COM_WRITE_COMPLETE         = 0x20
	SMB_COM_QUERY_SERVER           = 0x21
	SMB_COM_SET_INFORMATION2       = 0x22
	SMB_COM_QUERY_INFORMATION2     = 0x23
	SMB_COM_LOCKING_ANDX           = 0x24
	SMB_COM_TRANSACTION            = 0x25
	SMB_COM_TRANSACTION_SECONDARY  = 0x26
	SMB_COM_IOCTL                  = 0x27
	SMB_COM_IOCTL_SECONDARY        = 0x28
	SMB_COM_COPY                   = 0x29
	SMB_COM_MOVE                   = 0x2a
	SMB_COM_ECHO                   = 0x2b
	SMB_COM_WRITE_AND_CLOSE        = 0x2c
	SMB_COM_OPEN_ANDX              = 0x2d
	SMB_COM_READ_ANDX              = 0x2e
	SMB_COM_WRITE_ANDX             = 0x2f
	SMB_COM_NEW_FILE_SIZE          = 0x30
	SMB_COM_CLOSE_AND_TREE_DISC    = 0x31
	SMB_COM_TRANSACTION2           = 0x32
	SMB_COM_TRANSACTION2_SECONDARY = 0x33
	SMB_COM_FIND_CLOSE2            = 0x34
	SMB_COM_FIND_NOTIFY_CLOSE      = 0x35
	SMB_COM_TREE_CONNECT           = 0x70
	SMB_COM_TREE_DISCONNECT        = 0x71
	SMB_COM_NEGOTIATE              = 0x72
	SMB_COM_SESSION_SETUP_ANDX     = 0x73
	SMB_COM_LOGOFF_ANDX            = 0x74
	SMB_COM_TREE_CONNECT_ANDX      = 0x75
	SMB_COM_SECURITY_PACKAGE_ANDX  = 0x7e
	SMB_COM_QUERY_INFORMATION_DISK = 0x80
	SMB_COM_SEARCH                 = 0x81
	SMB_COM_FIND                   = 0x82
	SMB_COM_FIND_UNIQUE            = 0x83
	SMB_COM_FIND_CLOSE             = 0x84
	SMB_COM_NT_TRANSACT            = 0xa0
	SMB_COM_NT_TRANSACT_SECONDARY  = 0xa1
	SMB_COM_NT_CREATE_ANDX         = 0xa2
	SMB_COM_NT_CANCEL              = 0xa4
	SMB_COM_NT_RENAME              = 0xa5
	SMB_COM_OPEN_PRINT_FILE        = 0xc0
	SMB_COM_WRITE_PRINT_FILE       = 0xc1
	SMB_COM_CLOSE_PRINT_FILE       = 0xc2
	SMB_COM_GET_PRINT_QUEUE        = 0xc3
	SMB_COM_READ_BULK              = 0xd8
	SMB_COM_WRITE_BULK             = 0xd9
	SMB_COM_WRITE_BULK_DATA        = 0xda
	SMB_COM_INVALID                = 0xfe
	SMB_COM_NO_ANDX_COMMAND        = 0xff
)
