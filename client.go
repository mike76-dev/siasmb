package main

// smbClient represents a client connecting to a remote SMB share.
type smbClient struct {
	clientGuid [16]byte
	dialect    uint16
}
