package client

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mike76-dev/siasmb/smb2"
	"go.sia.tech/core/types"
	"go.sia.tech/renterd/v2/api"
	"golang.org/x/crypto/blake2b"
)

// Client implements a http.Client for interacting with renterd.
type Client struct {
	BaseURL  string
	Password string
}

// New returns an initialized Client.
func New(addr, password string) *Client {
	return &Client{
		BaseURL:  addr,
		Password: password,
	}
}

// GetBucket retrieves the information about a bucket.
func (c *Client) GetBucket(ctx context.Context, name string) (bucket api.Bucket, err error) {
	err = c.doRequest(ctx, "GET", fmt.Sprintf("/api/bus/bucket/%s", name), nil, &bucket)
	return
}

// GetObject retrieves the information about a file.
func (c *Client) GetObject(ctx context.Context, bucket, path string) (obj api.ObjectMetadata, err error) {
	values := url.Values{}
	values.Set("bucket", bucket)
	api.GetObjectOptions{OnlyMetadata: true}.Apply(values)
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	path = api.ObjectKeyEscape(path)
	path += "?" + values.Encode()
	var res api.Object
	err = c.doRequest(ctx, "GET", fmt.Sprintf("/api/bus/object/%s", path), nil, &res)
	if err != nil {
		return
	}
	obj = res.ObjectMetadata
	return
}

// GetObjects lists the contents of a directory.
func (c *Client) GetObjects(ctx context.Context, bucket, path string) (objs []api.ObjectMetadata, err error) {
	values := url.Values{}
	api.ListObjectOptions{
		Bucket:    bucket,
		Delimiter: "/",
		Limit:     -1,
	}.Apply(values)
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	path = api.ObjectKeyEscape(path)
	path += "?" + values.Encode()
	var res api.ObjectsResponse
	err = c.doRequest(ctx, "GET", fmt.Sprintf("/api/bus/objects/%s", path), nil, &res)
	if err != nil {
		return
	}
	objs = res.Objects
	return
}

// GetObjectInfo retrieves the information about a file or a directory.
func (c *Client) GetObjectInfo(ctx context.Context, bucket, path string) (api.ObjectMetadata, error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	if path == "" {                            // The root path: calculate the total size of the objects
		b, err := c.GetBucket(ctx, bucket)
		if err != nil {
			return api.ObjectMetadata{}, err
		}

		objs, err := c.GetObjects(ctx, bucket, "")
		if err != nil {
			return api.ObjectMetadata{}, err
		}

		var size int64
		for _, entry := range objs {
			size += entry.Size
		}

		return api.ObjectMetadata{
			Bucket:  bucket,
			ModTime: b.CreatedAt,
			Key:     "/",
			Size:    size,
		}, nil
	}

	var parentDir string
	i := strings.LastIndex(path, "/")
	if i < 0 {
		parentDir = ""
	} else {
		parentDir = path[:i+1]
	}

	objs, err := c.GetObjects(ctx, bucket, parentDir)
	if err != nil {
		return api.ObjectMetadata{}, err
	}

	for _, entry := range objs {
		if entry.Key == "/"+path || entry.Key == "/"+path+"/" {
			return entry, nil
		}
	}

	return api.ObjectMetadata{}, api.ErrObjectNotFound
}

// GetParentInfo retrieves the information about the current and the parent directories where the file is located.
func (c *Client) GetParentInfo(ctx context.Context, bucket, path string) (dir, parentDir smb2.FileInfo, err error) {
	var parent, grandParent, name, parentName string
	if path != "" {
		name = path + "/"
	}

	if i := strings.LastIndex(path, "/"); i >= 0 {
		parent = path[:i]
		if parent != "" {
			parentName = parent + "/"
		}

		if j := strings.LastIndex(parent, "/"); j >= 0 {
			grandParent = parent[:j]
		}
	}

	if parent != "" {
		parent += "/"
	}

	if grandParent != "" {
		grandParent += "/"
	}

	var b api.Bucket
	if parent == "" || grandParent == "" {
		b, err = c.GetBucket(ctx, bucket)
		if err != nil {
			return
		}
	}

	var objs []api.ObjectMetadata
	if parent != "" {
		objs, err = c.GetObjects(ctx, bucket, parent)
		if err != nil {
			return
		}

		for _, entry := range objs {
			if entry.Key == name {
				etag, _ := hex.DecodeString(entry.ETag)
				if len(etag) >= 8 {
					dir.ID64 = binary.LittleEndian.Uint64(etag[:8])
				}

				dir.CreatedAt = time.Time(entry.ModTime)
				dir.ID = make([]byte, 16)
				break
			}
		}
	} else {
		hash := blake2b.Sum256([]byte("/"))
		dir.ID64 = binary.LittleEndian.Uint64(hash[:8])
		dir.CreatedAt = time.Time(b.CreatedAt)
		dir.ID = make([]byte, 16)
	}

	if grandParent != "" {
		objs, err = c.GetObjects(ctx, bucket, grandParent)
		if err != nil {
			return
		}

		for _, entry := range objs {
			if entry.Key == parentName {
				etag, _ := hex.DecodeString(entry.ETag)
				if len(etag) >= 8 {
					parentDir.ID64 = binary.LittleEndian.Uint64(etag[:8])
				}

				parentDir.CreatedAt = time.Time(entry.ModTime)
				parentDir.ID = make([]byte, 16)
				break
			}
		}
	} else {
		hash := blake2b.Sum256([]byte("/"))
		parentDir.ID64 = binary.LittleEndian.Uint64(hash[:8])
		parentDir.CreatedAt = time.Time(b.CreatedAt)
		parentDir.ID = make([]byte, 16)
	}

	if parentDir.ID64 == dir.ID64 {
		parentDir.ID64 = 0
	}

	return
}

// Redundancy retrieves the renterd redundancy settings.
func (c *Client) Redundancy(ctx context.Context) (resp api.RedundancySettings, err error) {
	err = c.doRequest(ctx, "GET", "/api/bus/setting/redundancy", nil, &resp)
	return
}

// contracts retrieves the renterd contracts.
func (c *Client) contracts(ctx context.Context) (contracts []api.ContractMetadata, err error) {
	err = c.doRequest(ctx, "GET", "/api/bus/contracts", nil, &contracts)
	return
}

// host retrieves the information about a particular host by its public key.
func (c *Client) host(ctx context.Context, pk types.PublicKey) (h api.Host, err error) {
	err = c.doRequest(ctx, "GET", fmt.Sprintf("/api/bus/host/%s", pk), nil, &h)
	return
}

// RemainingStorage calculates the total remaining storage of all hosts that renterd has active contracts with.
func (c *Client) RemainingStorage(ctx context.Context) (rs uint64, err error) {
	var contracts []api.ContractMetadata
	contracts, err = c.contracts(ctx)
	if err != nil {
		return
	}
	for _, contract := range contracts {
		if contract.State != api.ContractStateActive {
			continue
		}
		var h api.Host
		h, err = c.host(ctx, contract.HostKey)
		if err != nil {
			return
		}
		rs += h.V2Settings.RemainingStorage
	}
	return rs, nil
}

// UsedStorage retrieves the "used" storage, meaning the total size of uploaded sectors including redundancy.
func (c *Client) UsedStorage(ctx context.Context, bucket string) (us uint64, err error) {
	values := url.Values{}
	values.Set("bucket", bucket)
	var osr api.ObjectsStatsResponse
	err = c.doRequest(ctx, "GET", "/api/bus/stats/objects?"+values.Encode(), nil, &osr)
	if err != nil {
		return
	}
	return osr.TotalUploadedSize, nil
}

// ReadObject downloads a file from the Sia network.
func (c *Client) ReadObject(ctx context.Context, bucket, path string, offset, length uint64, buf io.Writer) (err error) {
	values := url.Values{}
	values.Set("bucket", bucket)

	// url.PathEscape does the full escape, so we need to convert any escaped forward slashes back.
	path = strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
	path = fmt.Sprintf("/api/worker/objects/%s?"+values.Encode(), path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%v%v", c.BaseURL, path), nil)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	if c.Password != "" {
		req.SetBasicAuth("", c.Password)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer io.Copy(io.Discard, resp.Body)
	defer resp.Body.Close()
	if !(200 <= resp.StatusCode && resp.StatusCode < 300) {
		err, _ := io.ReadAll(resp.Body)
		return errors.New(string(err))
	}

	if resp == nil {
		return nil
	}

	_, err = io.Copy(buf, resp.Body)
	return
}

// StartUpload initiates a multipart upload.
func (c *Client) StartUpload(ctx context.Context, bucket, path string) (uploadID string, err error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	var resp api.MultipartCreateResponse
	if err = c.doRequest(ctx, "POST", "/api/bus/multipart/create", api.MultipartCreateRequest{
		Bucket: bucket,
		Key:    "/" + path,
	}, &resp); err != nil {
		return
	}
	return resp.UploadID, nil
}

// AbortUpload aborts an initiated multipart upload.
func (c *Client) AbortUpload(ctx context.Context, bucket, path string, uploadID string) (err error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	err = c.doRequest(ctx, "POST", "/api/bus/multipart/abort", api.MultipartAbortRequest{
		Bucket:   bucket,
		Key:      "/" + path,
		UploadID: uploadID,
	}, nil)
	return
}

// FinishUpload completes a multipart upload.
func (c *Client) FinishUpload(ctx context.Context, bucket, path string, uploadID string, parts []api.MultipartCompletedPart) (eTag string, err error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one

	// The parts may come out of order, but renterd will error back, so we need to sort them.
	slices.SortFunc(parts, func(a, b api.MultipartCompletedPart) int { return a.PartNumber - b.PartNumber })
	var resp api.MultipartCompleteResponse
	if err = c.doRequest(ctx, "POST", "/api/bus/multipart/complete", api.MultipartCompleteRequest{
		Bucket:   bucket,
		Key:      "/" + path,
		UploadID: uploadID,
		Parts:    parts,
	}, &resp); err != nil {
		return
	}
	return resp.ETag, nil
}

// UploadPart uploads the provided chunk of data to the Sia network.
func (c *Client) UploadPart(ctx context.Context, r io.Reader, bucket, path, uploadID string, partNumber int, offset, length uint64) (eTag string, err error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	path = api.ObjectKeyEscape(path)
	values := make(url.Values)
	values.Set("bucket", bucket)
	values.Set("uploadid", uploadID)
	values.Set("partnumber", fmt.Sprint(partNumber))

	off := int(offset)
	opts := api.UploadMultipartUploadPartOptions{
		EncryptionOffset: &off,
		ContentLength:    int64(length),
	}
	opts.Apply(values)

	u, err := url.Parse(fmt.Sprintf("%v/api/worker/multipart/%v", c.BaseURL, path))
	if err != nil {
		return
	}
	u.RawQuery = values.Encode()

	req, err := http.NewRequestWithContext(ctx, "PUT", u.String(), r)
	if err != nil {
		return
	}

	req.SetBasicAuth("", c.Password)
	if length != 0 {
		req.ContentLength = int64(length)
	} else if req.ContentLength, err = sizeFromSeeker(r); err != nil {
		return "", fmt.Errorf("failed to get content length from seeker: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lr := io.LimitReader(resp.Body, 1<<20) // 1MiB limit
		errMsg, _ := io.ReadAll(lr)
		return "", fmt.Errorf("HTTP error: %s (status: %d)", string(errMsg), resp.StatusCode)
	}

	return resp.Header.Get("ETag"), nil
}

// DeleteObject deletes a file or a directory.
func (c *Client) DeleteObject(ctx context.Context, bucket, path string, batch bool) (err error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	path = api.ObjectKeyEscape(path)
	if batch {
		err = c.doRequest(ctx, "POST", "/api/worker/objects/remove", api.ObjectsRemoveRequest{
			Bucket: bucket,
			Prefix: path,
		}, nil)
	} else {
		values := make(url.Values)
		values.Set("bucket", bucket)
		err = c.doRequest(ctx, "DELETE", fmt.Sprintf("/api/worker/objects/%s?"+values.Encode(), path), nil, nil)
	}
	return
}

// MakeDirectory creates a new directory in the specified path.
func (c *Client) MakeDirectory(ctx context.Context, bucket, path string) (err error) {
	path = strings.ReplaceAll(path, "\\", "/") // Replace Windows formatting with the unified one
	path = api.ObjectKeyEscape(path)
	path += "/"
	values := make(url.Values)
	values.Set("bucket", bucket)
	err = c.doRequest(ctx, "PUT", fmt.Sprintf("/api/worker/objects/%s?"+values.Encode(), path), nil, nil)
	return
}

// RenameObject renames a file or a directory.
func (c *Client) RenameObject(ctx context.Context, bucket, oldName, newName string, isDir, force bool) (err error) {
	mode := api.ObjectsRenameModeSingle
	if isDir {
		oldName += "/"
		newName += "/"
		mode = api.ObjectsRenameModeMulti
	}
	err = c.doRequest(ctx, "POST", "/api/bus/objects/rename", api.ObjectsRenameRequest{
		Bucket: bucket,
		Force:  force,
		From:   "/" + oldName,
		To:     "/" + newName,
		Mode:   mode,
	}, nil)
	return
}

// sizeFromSeeker tries to find out the size of a file.
func sizeFromSeeker(r io.Reader) (int64, error) {
	s, ok := r.(io.Seeker)
	if !ok {
		return 0, nil
	}
	size, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	_, err = s.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// doRequest does everything needed to send an HTTP request and receive a response.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, resp interface{}) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.Password != "" {
		req.SetBasicAuth("", c.Password)
	}

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode < 200 || r.StatusCode >= 300 {
		errMsg, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MiB limit
		return fmt.Errorf("HTTP error: %s (status: %d)", string(errMsg), r.StatusCode)
	}

	if resp != nil {
		return json.NewDecoder(r.Body).Decode(resp)
	}

	return nil
}
