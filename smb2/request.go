package smb2

type Request struct {
	MessageID       uint64
	AsyncID         uint64
	CancelRequestID uint64
	// Open
	// IsEncrypted: 3.x
	// TransformSessionId 3.x
	// CompressReply 3.1.1
	Header *Header
	Body   []byte
}
