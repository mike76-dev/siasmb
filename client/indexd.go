package client

import (
	"context"
	"io"

	"go.sia.tech/renterd/v2/api"
)

// indexdClient implements a Client for interacting with indexd.
type indexdClient struct {
	clientParams
}

// newIndexdClient returns an initialized indexdClient.
func newIndexdClient(addr, password string) Client {
	return &indexdClient{
		clientParams: clientParams{
			baseURL:  addr,
			password: password,
		},
	}
}

// Info queries the general information about the share.
func (ic *indexdClient) Info(ctx context.Context, bucketName string) (GeneralInfo, error) {
	return GeneralInfo{}, nil
}

// Storage queries the information about the underlying storage.
func (ic *indexdClient) Storage(ctx context.Context, bucket string) (StorageInfo, error) {
	return StorageInfo{}, nil
}

// IsEmpty returns true if the directory contains at least one object.
func (ic *indexdClient) IsEmpty(ctx context.Context, bucket, path string) (bool, error) {
	return true, nil
}

// List lists the contents of a directory.
func (ic *indexdClient) List(ctx context.Context, bucket, path string) (ois []ObjectInfo, err error) {
	return
}

// Object retrieves the information about a file or a directory.
func (ic *indexdClient) Object(ctx context.Context, bucket, path string) (ObjectInfo, error) {
	return ObjectInfo{}, nil
}

// Parents retrieves the information about the current and the parent directories where the file is located.
func (ic *indexdClient) Parents(ctx context.Context, bucket, path string) (currentDir, parentDir FileInfo, err error) {
	return
}

// Read downloads a file from the Sia network.
func (ic *indexdClient) Read(ctx context.Context, bucket, path string, offset, length uint64, buf io.Writer) (err error) {
	return
}

// StartUpload initiates a multipart upload.
func (ic *indexdClient) StartUpload(ctx context.Context, bucket, path string) (uploadID string, err error) {
	return "", nil
}

// AbortUpload aborts an initiated multipart upload.
func (ic *indexdClient) AbortUpload(ctx context.Context, bucket, path string, uploadID string) (err error) {
	return
}

// FinishUpload completes a multipart upload.
func (ic *indexdClient) FinishUpload(ctx context.Context, bucket, path string, uploadID string, parts []api.MultipartCompletedPart) error {
	return nil
}

// Write uploads the provided chunk of data to the Sia network.
func (ic *indexdClient) Write(ctx context.Context, r io.Reader, bucket, path string, uploadID string, partNumber int, offset, length uint64) (eTag string, err error) {
	return
}

// Delete deletes a file or a directory.
func (ic *indexdClient) Delete(ctx context.Context, bucket, path string, batch bool) (err error) {
	return
}

// MakeDirectory creates a new directory in the specified path.
func (ic *indexdClient) MakeDirectory(ctx context.Context, bucket, path string) error {
	return nil
}

// Rename renames a file or a directory.
func (ic *indexdClient) Rename(ctx context.Context, bucket, oldName, newName string, isDir, force bool) error {
	return nil
}
