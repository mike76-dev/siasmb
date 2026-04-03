package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/mike76-dev/siasmb/stores"
	proto "go.sia.tech/core/rhp/v4"
	"go.sia.tech/indexd/sdk"
	"go.sia.tech/renterd/v2/api"
	"golang.org/x/crypto/blake2b"
)

// IndexdClient implements a Client for interacting with indexd.
type IndexdClient struct {
	share        string
	db           *stores.Database
	sdkClient    *sdk.SDK
	dataShards   uint8
	parityShards uint8
}

// NewIndexdClient returns an initialized IndexdClient.
func NewIndexdClient(db *stores.Database, sdkClient *sdk.SDK, share string, dataShards, parityShards uint8) Client {
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
		MinShards:        int(ic.dataShards),
		TotalShards:      int(ic.parityShards + ic.dataShards),
	}, nil
}

// IsEmpty returns true if the directory contains at least one object.
func (ic *IndexdClient) IsEmpty(ctx context.Context, acc stores.Account, path string) (bool, error) {
	return ic.db.DirectoryEmpty(acc, ic.share, path)
}

// List lists the contents of a directory.
func (ic *IndexdClient) List(ctx context.Context, acc stores.Account, path string) (ois []ObjectInfo, err error) {
	oms, err := ic.db.ListObjects(acc, ic.share, path)
	if err != nil {
		return nil, err
	}

	for _, om := range oms {
		oi := ObjectInfo{
			Key:        om.Path,
			CreatedAt:  om.CreatedAt,
			ModifiedAt: om.ModifiedAt,
			Size:       om.Size,
		}
		if om.IsDir && om.Path != "/" {
			oi.Key += "/"
		}
		ois = append(ois, oi)
	}

	return ois, nil
}

// Object retrieves the information about a file or a directory.
func (ic *IndexdClient) Object(ctx context.Context, acc stores.Account, path string) (ObjectInfo, error) {
	if path == "" {
		info, err := ic.Info(ctx)
		if err != nil {
			return ObjectInfo{}, err
		}

		return ObjectInfo{
			Key:        "/",
			CreatedAt:  info.CreatedAt,
			ModifiedAt: info.CreatedAt,
			Size:       0,
		}, nil
	}

	om, err := ic.db.Object(acc, ic.share, path)
	if err != nil {
		return ObjectInfo{}, err
	}

	oi := ObjectInfo{
		Key:        om.Path,
		CreatedAt:  om.CreatedAt,
		ModifiedAt: om.ModifiedAt,
		Size:       om.Size,
	}

	if om.IsDir && om.Path != "/" {
		oi.Key += "/"
	}

	return oi, nil
}

// hashPath is a helper function that calculates the hash of a path.
func hashPath(acc stores.Account, path string) [32]byte {
	return blake2b.Sum256(append([]byte(acc.Username), []byte(acc.Workgroup+path)...))
}

// Parents retrieves the information about the current and the parent directories where the file is located.
func (ic *IndexdClient) Parents(ctx context.Context, acc stores.Account, path string) (currentDir, parentDir FileInfo, err error) {
	current, parent, err := ic.db.CurrentAndParent(acc, ic.share, path)
	if err != nil {
		return
	}

	var info GeneralInfo
	var rootHash [32]byte
	if (current.Path == "") || (parent.Path == "") {
		info, err = ic.Info(ctx)
		if err != nil {
			return
		}
		rootHash = hashPath(acc, "/")
	}

	currentDir.ID = make([]byte, 16)
	if current.Path == "" {
		currentDir.ID64 = binary.LittleEndian.Uint64(rootHash[:8])
		currentDir.CreatedAt = info.CreatedAt
		currentDir.ModifiedAt = info.CreatedAt
		copy(currentDir.ID, rootHash[:16])
	} else {
		hash := hashPath(acc, current.Path)
		currentDir.ID64 = binary.LittleEndian.Uint64(hash[:8])
		currentDir.CreatedAt = current.CreatedAt
		currentDir.ModifiedAt = current.ModifiedAt
		copy(currentDir.ID, hash[:16])
	}

	parentDir.ID = make([]byte, 16)
	if parent.Path == "" {
		parentDir.ID64 = binary.LittleEndian.Uint64(rootHash[:8])
		parentDir.CreatedAt = info.CreatedAt
		parentDir.ModifiedAt = info.CreatedAt
		copy(parentDir.ID, rootHash[:16])
	} else {
		hash := hashPath(acc, parent.Path)
		parentDir.ID64 = binary.LittleEndian.Uint64(hash[:8])
		parentDir.CreatedAt = parent.CreatedAt
		parentDir.ModifiedAt = parent.ModifiedAt
		copy(parentDir.ID, hash[:16])
	}

	return
}

// Read downloads a file from the Sia network.
func (ic *IndexdClient) Read(ctx context.Context, path string, offset, length uint64, buf io.Writer) (err error) {
	return
}

// StartUpload initiates a multipart upload.
func (ic *IndexdClient) StartUpload(ctx context.Context, acc stores.Account, path string) (uploadID string, err error) {
	return ic.db.CreateUpload(acc, ic.share, path, true)
}

// AbortUpload aborts an initiated multipart upload.
func (ic *IndexdClient) AbortUpload(ctx context.Context, _ string, uploadID string) (err error) {
	parts, err := ic.db.ListUploadParts(uploadID)
	if err != nil {
		return fmt.Errorf("couldn't retrieve upload parts: %v", err)
	}

	for _, part := range parts {
		if err := ic.sdkClient.DeleteObject(ctx, part); err != nil {
			return fmt.Errorf("couldn't delete slab: %v", err)
		}
	}

	return ic.db.RemoveUpload(uploadID)
}

// FinishUpload completes a multipart upload.
func (ic *IndexdClient) FinishUpload(ctx context.Context, path string, uploadID string, _ []api.MultipartCompletedPart) error {
	if err := ic.db.FinalizeUpload(uploadID); err != nil {
		return fmt.Errorf("couldn't finalize upload: %v", err)
	}

	return nil
}

// Write uploads the provided chunk of data to the Sia network.
func (ic *IndexdClient) Write(ctx context.Context, r io.Reader, path string, uploadID string, partNumber int, offset, length uint64) (_ string, err error) {
	if length >= proto.SectorSize*uint64(ic.dataShards) {
		obj := sdk.NewEmptyObject()
		err = ic.sdkClient.Upload(ctx, &obj, r, sdk.WithRedundancy(ic.dataShards, ic.parityShards))
		if err != nil {
			return "", fmt.Errorf("couldn't upload slab: %v", err)
		}

		if err := ic.sdkClient.PinObject(ctx, obj); err != nil {
			return "", fmt.Errorf("couldn't pin slab: %v", err)
		}

		key := obj.ID()
		if err = ic.db.AddPart(uploadID, partNumber, offset, 0, length, key[:]); err != nil {
			return "", fmt.Errorf("couldn't add part to the database: %v", err)
		}
	} else {
		buf, err := io.ReadAll(r)
		if err != nil {
			return "", fmt.Errorf("couldn't read data: %v", err)
		}

		if err = ic.db.AddPartialData(uploadID, partNumber, offset, buf); err != nil {
			return "", fmt.Errorf("couldn't add partial data to the database: %v", err)
		}
	}

	return
}

// Delete deletes a file or a directory.
func (ic *IndexdClient) Delete(ctx context.Context, acc stores.Account, path string, batch bool) (err error) {
	slabs, err := ic.db.ListSlabs(acc, ic.share, path)
	if err != nil {
		return err
	}

	for _, key := range slabs {
		if err := ic.sdkClient.DeleteObject(ctx, key); err != nil {
			log.Printf("failed to delete slab %x from %s", key, path)
		}
	}

	if batch {
		return ic.db.DeleteDirectory(acc, ic.share, path)
	}

	return ic.db.DeleteFile(acc, ic.share, path)
}

// MakeDirectory creates a new directory in the specified path.
func (ic *IndexdClient) MakeDirectory(ctx context.Context, acc stores.Account, path string) error {
	return ic.db.CreateDirectory(acc, ic.share, path, true)
}

// Rename renames a file or a directory.
func (ic *IndexdClient) Rename(ctx context.Context, acc stores.Account, oldName, newName string, isDir, force bool) error {
	if isDir {
		return ic.db.RenameDirectory(acc, ic.share, oldName, newName, force)
	}
	return ic.db.RenameFile(acc, ic.share, oldName, newName, force)
}
