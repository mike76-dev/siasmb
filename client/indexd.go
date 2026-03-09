package client

import (
	"context"
	"errors"
	"io"

	"github.com/mike76-dev/siasmb/stores"
	"go.sia.tech/indexd/sdk"
	"go.sia.tech/renterd/v2/api"
)

var (
	ErrUnauthenticated = errors.New("no account provided")
)

// IndexdClient implements a Client for interacting with indexd.
type IndexdClient struct {
	db        *stores.Database
	sdkClient *sdk.SDK
}

// NewIndexdClient returns an initialized IndexdClient.
func NewIndexdClient(db *stores.Database, sdkClient *sdk.SDK) Client {
	return &IndexdClient{
		db:        db,
		sdkClient: sdkClient,
	}
}

// Info queries the general information about the share.
func (ic *IndexdClient) Info(ctx context.Context, bucketName string) (GeneralInfo, error) {
	return GeneralInfo{}, nil
}

// Storage queries the information about the underlying storage.
func (ic *IndexdClient) Storage(ctx context.Context, bucket string) (StorageInfo, error) {
	return StorageInfo{}, nil
}

// IsEmpty returns true if the directory contains at least one object.
func (ic *IndexdClient) IsEmpty(ctx context.Context, bucket, path string) (bool, error) {
	return true, nil
}

// List lists the contents of a directory.
func (ic *IndexdClient) List(ctx context.Context, bucket, path string) (ois []ObjectInfo, err error) {
	return
}

// Object retrieves the information about a file or a directory.
func (ic *IndexdClient) Object(ctx context.Context, bucket, path string) (ObjectInfo, error) {
	return ObjectInfo{}, nil
}

// Parents retrieves the information about the current and the parent directories where the file is located.
func (ic *IndexdClient) Parents(ctx context.Context, bucket, path string) (currentDir, parentDir FileInfo, err error) {
	return
}

// Read downloads a file from the Sia network.
func (ic *IndexdClient) Read(ctx context.Context, bucket, path string, offset, length uint64, buf io.Writer) (err error) {
	return
}

// StartUpload initiates a multipart upload.
func (ic *IndexdClient) StartUpload(ctx context.Context, bucket, path string) (uploadID string, err error) {
	return "", nil
}

// AbortUpload aborts an initiated multipart upload.
func (ic *IndexdClient) AbortUpload(ctx context.Context, bucket, path string, uploadID string) (err error) {
	return
}

// FinishUpload completes a multipart upload.
func (ic *IndexdClient) FinishUpload(ctx context.Context, bucket, path string, uploadID string, parts []api.MultipartCompletedPart) error {
	return nil
}

// Write uploads the provided chunk of data to the Sia network.
func (ic *IndexdClient) Write(ctx context.Context, r io.Reader, bucket, path string, uploadID string, partNumber int, offset, length uint64) (eTag string, err error) {
	return
}

// Delete deletes a file or a directory.
func (ic *IndexdClient) Delete(ctx context.Context, bucket, path string, batch bool) (err error) {
	return
}

// MakeDirectory creates a new directory in the specified path.
func (ic *IndexdClient) MakeDirectory(ctx context.Context, bucket, path string) error {
	return nil
}

// Rename renames a file or a directory.
func (ic *IndexdClient) Rename(ctx context.Context, bucket, oldName, newName string, isDir, force bool) error {
	return nil
}
