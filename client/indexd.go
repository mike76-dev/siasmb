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
	share        string
	db           *stores.Database
	sdkClient    *sdk.SDK
	dataShards   int
	parityShards int
}

// NewIndexdClient returns an initialized IndexdClient.
func NewIndexdClient(db *stores.Database, sdkClient *sdk.SDK, share string, dataShards, parityShards int) Client {
	return &IndexdClient{
		share:        share,
		db:           db,
		sdkClient:    sdkClient,
		dataShards:   dataShards,
		parityShards: parityShards,
	}
}

// Info queries the general information about the share.
func (ic *IndexdClient) Info(ctx context.Context) (GeneralInfo, error) {
	sh, err := ic.db.GetShare(ic.share)
	if err != nil {
		return GeneralInfo{}, err
	}

	return GeneralInfo{
		Bucket:    "",
		CreatedAt: sh.CreatedAt,
	}, nil
}

// Storage queries the information about the underlying storage.
func (ic *IndexdClient) Storage(ctx context.Context) (StorageInfo, error) {
	acc, err := ic.sdkClient.Account(ctx)
	if err != nil {
		return StorageInfo{}, err
	}

	return StorageInfo{
		Type:             "indexd",
		RemainingStorage: acc.MaxPinnedData - acc.PinnedData,
		UsedStorage:      acc.PinnedData,
		MinShards:        ic.dataShards,
		TotalShards:      ic.parityShards + ic.dataShards,
	}, nil
}

// IsEmpty returns true if the directory contains at least one object.
func (ic *IndexdClient) IsEmpty(ctx context.Context, path string) (bool, error) {
	return true, nil
}

// List lists the contents of a directory.
func (ic *IndexdClient) List(ctx context.Context, path string) (ois []ObjectInfo, err error) {
	return
}

// Object retrieves the information about a file or a directory.
func (ic *IndexdClient) Object(ctx context.Context, path string) (ObjectInfo, error) {
	return ObjectInfo{}, nil
}

// Parents retrieves the information about the current and the parent directories where the file is located.
func (ic *IndexdClient) Parents(ctx context.Context, path string) (currentDir, parentDir FileInfo, err error) {
	return
}

// Read downloads a file from the Sia network.
func (ic *IndexdClient) Read(ctx context.Context, path string, offset, length uint64, buf io.Writer) (err error) {
	return
}

// StartUpload initiates a multipart upload.
func (ic *IndexdClient) StartUpload(ctx context.Context, path string) (uploadID string, err error) {
	return "", nil
}

// AbortUpload aborts an initiated multipart upload.
func (ic *IndexdClient) AbortUpload(ctx context.Context, path string, uploadID string) (err error) {
	return
}

// FinishUpload completes a multipart upload.
func (ic *IndexdClient) FinishUpload(ctx context.Context, path string, uploadID string, parts []api.MultipartCompletedPart) error {
	return nil
}

// Write uploads the provided chunk of data to the Sia network.
func (ic *IndexdClient) Write(ctx context.Context, r io.Reader, path string, uploadID string, partNumber int, offset, length uint64) (eTag string, err error) {
	return
}

// Delete deletes a file or a directory.
func (ic *IndexdClient) Delete(ctx context.Context, path string, batch bool) (err error) {
	return
}

// MakeDirectory creates a new directory in the specified path.
func (ic *IndexdClient) MakeDirectory(ctx context.Context, path string) error {
	return nil
}

// Rename renames a file or a directory.
func (ic *IndexdClient) Rename(ctx context.Context, oldName, newName string, isDir, force bool) error {
	return nil
}
