package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/mike76-dev/siasmb/stores"
	proto "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/indexd/slabs"
	"go.sia.tech/renterd/v2/api"
	sdk "go.sia.tech/siastorage"
	"golang.org/x/crypto/blake2b"
)

// IndexdClient implements a Client for interacting with indexd.
type IndexdClient struct {
	share        string
	db           *stores.Database
	sdkClient    *sdk.SDK
	dataShards   uint8
	parityShards uint8
	closeChan    chan struct{}
}

// NewIndexdClient returns an initialized IndexdClient.
func NewIndexdClient(db *stores.Database, sdkClient *sdk.SDK, share string, dataShards, parityShards uint8) Client {
	cc := make(chan struct{})
	ic := &IndexdClient{
		share:        share,
		db:           db,
		sdkClient:    sdkClient,
		dataShards:   dataShards,
		parityShards: parityShards,
		closeChan:    cc,
	}

	// Start background upload thread.
	go ic.processUploads(ic.closeChan)

	return ic
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
func (ic *IndexdClient) Read(ctx context.Context, acc stores.Account, path string, offset, length uint64, buf io.Writer) (err error) {
	slabs, err := ic.db.GetMetadata(acc, ic.share, path)
	if err != nil {
		return err
	}

	end := offset + length

	for _, slab := range slabs {
		slabStart := slab.At
		slabEnd := slab.At + slab.Length
		if slabEnd <= offset {
			continue
		}
		if slabStart >= end {
			break
		}

		readStart := max(offset, slabStart)
		readEnd := min(end, slabEnd)
		rangeOffset := slab.Offset + (readStart - slabStart)
		rangeLength := readEnd - readStart

		if (slab.Key != types.Hash256{}) {
			obj, err := ic.sdkClient.Object(ctx, slab.Key)
			if err != nil {
				return err
			}

			if err = ic.sdkClient.Download(ctx, buf, obj, sdk.WithDownloadRange(rangeOffset, rangeLength)); err != nil {
				return err
			}
		} else if slab.Data != nil {
			if _, err = io.Copy(buf, bytes.NewReader(slab.Data[readStart-slabStart:readEnd-slabStart])); err != nil {
				return err
			}
		}
	}

	return nil
}

// StartUpload initiates a multipart upload.
func (ic *IndexdClient) StartUpload(ctx context.Context, acc stores.Account, path string) (uploadID string, err error) {
	return ic.db.CreateUpload(acc, ic.share, path)
}

// AbortUpload aborts an initiated multipart upload.
func (ic *IndexdClient) AbortUpload(ctx context.Context, _ string, uploadID string) (err error) {
	slabs, err := ic.db.RemoveUpload(uploadID)
	if err != nil {
		return fmt.Errorf("couldn't abort upload: %v", err)
	}

	for _, key := range slabs {
		if err := ic.sdkClient.DeleteObject(ctx, key); err != nil {
			return fmt.Errorf("couldn't delete slab: %v", err)
		}
	}

	if err := ic.sdkClient.PruneSlabs(ctx); err != nil {
		return fmt.Errorf("couldn't prune slabs: %v", err)
	}

	return nil
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
	buf, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("couldn't read data: %v", err)
	}
	if uint64(len(buf)) != length {
		return "", fmt.Errorf("short read: expected %d bytes, got %d", length, len(buf))
	}

	if err := ic.db.AddBufferedSlab(uploadID, offset, buf); err != nil {
		return "", fmt.Errorf("couldn't add buffered slab to the database: %v", err)
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

	if err := ic.sdkClient.PruneSlabs(ctx); err != nil {
		return fmt.Errorf("couldn't prune slabs: %v", err)
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

// DeleteAll deletes all objects on the share. This is used when a share is removed to ensure
// that all data is deleted from the Sia network.
func (ic *IndexdClient) DeleteAll(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		objs, err := ic.sdkClient.ListObjects(ctx, slabs.Cursor{}, 10)
		if err != nil {
			return fmt.Errorf("couldn't list objects: %v", err)
		}
		if len(objs) == 0 {
			break
		}

		for _, obj := range objs {
			if err := ic.sdkClient.DeleteObject(ctx, obj.ID()); err != nil {
				log.Printf("couldn't delete object %x: %v", obj.ID(), err)
			}
		}
	}

	if err := ic.sdkClient.PruneSlabs(ctx); err != nil {
		return fmt.Errorf("couldn't prune slabs: %v", err)
	}

	return nil
}

// Close closes the client and releases all resources.
func (ic *IndexdClient) Close() error {
	close(ic.closeChan)
	return ic.sdkClient.Close()
}

// processUpload checks if there is a complete slab and uploads it.
func (ic *IndexdClient) processUpload(ctx context.Context) error {
	job, err := ic.db.ClaimUploadJob(uint64(ic.dataShards) * proto.SectorSize)
	if err != nil {
		return err
	}

	obj := sdk.NewEmptyObject()
	if err := ic.sdkClient.Upload(ctx, &obj, bytes.NewReader(job.Data), sdk.WithRedundancy(ic.dataShards, ic.parityShards)); err != nil {
		_ = ic.db.RequeueUploadJob(job.UploadID, job.MetadataID)
		return fmt.Errorf("couldn't upload slab: %v", err)
	}

	if err := ic.sdkClient.PinObject(ctx, obj); err != nil {
		_ = ic.db.RequeueUploadJob(job.UploadID, job.MetadataID)
		return fmt.Errorf("couldn't pin slab: %v", err)
	}

	key := obj.ID()
	if err := ic.db.CompleteUploadJob(job.MetadataID, job.BufferID, key); err != nil {
		return fmt.Errorf("couldn't complete upload job: %v", err)
	}

	return nil
}

// processUploads runs the upload jobs in the background.
func (ic *IndexdClient) processUploads(closeChan chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		select {
		case <-closeChan:
			return
		default:
		}

		if err := ic.processUpload(ctx); err != nil {
			time.Sleep(time.Second)
			if errors.Is(err, stores.ErrNoUploadJobs) {
				continue
			}
			log.Printf("failed to run upload job: %v", err)
		}
	}
}
