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

	"go.sia.tech/jape"
	"go.sia.tech/renterd/api"
	"golang.org/x/crypto/blake2b"
)

type Client struct {
	c jape.Client
}

func New(addr, password string) *Client {
	return &Client{jape.Client{
		BaseURL:  addr,
		Password: password,
	}}
}

func (c *Client) GetBucket(ctx context.Context, name string) (bucket api.Bucket, err error) {
	err = c.c.WithContext(ctx).GET(fmt.Sprintf("/api/bus/bucket/%s", name), &bucket)
	return
}

func (c *Client) GetObject(ctx context.Context, bucket, path string) (obj api.ObjectsResponse, err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	path = api.ObjectPathEscape(path)
	path += "?bucket=" + bucket
	err = c.c.WithContext(ctx).GET(fmt.Sprintf("/api/bus/objects/%s", path), &obj)
	return
}

func (c *Client) GetObjectInfo(ctx context.Context, bucket, path string) (info api.ObjectMetadata, err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	var resp api.ObjectsResponse
	if path == "" {
		var b api.Bucket
		b, err = c.GetBucket(ctx, bucket)
		if err != nil {
			return
		}

		resp, err = c.GetObject(ctx, bucket, "")
		if err != nil {
			return
		}

		var size int64
		for _, obj := range resp.Entries {
			size += obj.Size
		}

		info = api.ObjectMetadata{
			ETag:    "",
			ModTime: b.CreatedAt,
			Name:    "/",
			Size:    size,
		}

		return
	}

	var parentDir string
	i := strings.LastIndex(path, "/")
	if i < 0 {
		parentDir = ""
	} else {
		parentDir = path[:i+1]
	}

	resp, err = c.GetObject(ctx, bucket, parentDir)
	if err != nil {
		return
	}

	for _, obj := range resp.Entries {
		if obj.Name == "/"+path || obj.Name == "/"+path+"/" {
			info = obj
			return
		}
	}

	return api.ObjectMetadata{}, api.ErrObjectNotFound
}

func (c *Client) GetParentInfo(ctx context.Context, bucket, path string) (id, parentID uint64, createdAt, parentCreatedAt api.TimeRFC3339, err error) {
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

	var resp api.ObjectsResponse
	if parent != "" {
		resp, err = c.GetObject(ctx, bucket, parent)
		if err != nil {
			return
		}

		for _, entry := range resp.Entries {
			if entry.Name == name {
				etag, _ := hex.DecodeString(entry.ETag)
				if len(etag) >= 8 {
					id = binary.LittleEndian.Uint64(etag[:8])
				}

				createdAt = entry.ModTime
				break
			}
		}
	} else {
		hash := blake2b.Sum256([]byte("/"))
		id = binary.LittleEndian.Uint64(hash[:8])
		createdAt = b.CreatedAt
	}

	if grandParent != "" {
		resp, err = c.GetObject(ctx, bucket, grandParent)
		if err != nil {
			return
		}

		for _, entry := range resp.Entries {
			if entry.Name == parentName {
				etag, _ := hex.DecodeString(entry.ETag)
				if len(etag) >= 8 {
					parentID = binary.LittleEndian.Uint64(etag[:8])
				}

				parentCreatedAt = entry.ModTime
				break
			}
		}
	} else {
		hash := blake2b.Sum256([]byte("/"))
		parentID = binary.LittleEndian.Uint64(hash[:8])
		parentCreatedAt = b.CreatedAt
	}

	if parentID == id {
		parentID = 0
	}

	return
}

func (c *Client) SectorPerSlab(ctx context.Context) (sps int, err error) {
	var resp api.RedundancySettings
	err = c.c.WithContext(ctx).GET("/api/bus/setting/redundancy", &resp)
	if err != nil {
		return
	}

	return resp.MinShards, nil
}

func (c *Client) ReadObject(ctx context.Context, bucket, path string, offset, length uint64, buf io.Writer) (err error) {
	values := url.Values{}
	values.Set("bucket", bucket)

	path = strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
	path = fmt.Sprintf("/api/worker/objects/%s?"+values.Encode(), path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%v%v", c.c.BaseURL, path), nil)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	if c.c.Password != "" {
		req.SetBasicAuth("", c.c.Password)
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

func (c *Client) StartUpload(ctx context.Context, bucket, path string) (uploadID string, err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	var resp api.MultipartCreateResponse
	if err = c.c.WithContext(ctx).POST("/api/bus/multipart/create", api.MultipartCreateRequest{
		Bucket: bucket,
		Path:   "/" + path,
	}, &resp); err != nil {
		return
	}
	return resp.UploadID, nil
}

func (c *Client) AbortUpload(ctx context.Context, bucket, path string, uploadID string) (err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	err = c.c.WithContext(ctx).POST("/api/bus/multipart/abort", api.MultipartAbortRequest{
		Bucket:   bucket,
		Path:     "/" + path,
		UploadID: uploadID,
	}, nil)
	return
}

func (c *Client) FinishUpload(ctx context.Context, bucket, path string, uploadID string, parts []api.MultipartCompletedPart) (eTag string, err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	slices.SortFunc(parts, func(a, b api.MultipartCompletedPart) int { return a.PartNumber - b.PartNumber })
	var resp api.MultipartCompleteResponse
	if err = c.c.WithContext(ctx).POST("/api/bus/multipart/complete", api.MultipartCompleteRequest{
		Bucket:   bucket,
		Path:     "/" + path,
		UploadID: uploadID,
		Parts:    parts,
	}, &resp); err != nil {
		return
	}
	return resp.ETag, nil
}

func (c *Client) UploadPart(ctx context.Context, r io.Reader, bucket, path, uploadID string, partNumber int, offset, length uint64) (eTag string, err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	path = api.ObjectPathEscape(path)
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
	u, err := url.Parse(fmt.Sprintf("%v/api/worker/multipart/%v", c.c.BaseURL, path))
	if err != nil {
		return
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(ctx, "PUT", u.String(), r)
	if err != nil {
		return
	}
	req.SetBasicAuth("", c.c.WithContext(ctx).Password)
	if length != 0 {
		req.ContentLength = int64(length)
	} else if req.ContentLength, err = sizeFromSeeker(r); err != nil {
		return "", fmt.Errorf("failed to get content length from seeker: %v", err)
	}
	header, _, err := doRequest(req, nil)
	if err != nil {
		return "", err
	}
	return header.Get("ETag"), nil
}

func (c *Client) DeleteObject(ctx context.Context, bucket, path string, batch bool) (err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	path = api.ObjectPathEscape(path)
	if batch {
		path += "/"
	}
	values := make(url.Values)
	values.Set("bucket", bucket)
	opts := api.DeleteObjectOptions{Batch: batch}
	opts.Apply(values)
	err = c.c.WithContext(ctx).DELETE(fmt.Sprintf("/api/worker/objects/%s?"+values.Encode(), path))
	return
}

func (c *Client) MakeDirectory(ctx context.Context, bucket, path string) (err error) {
	path = strings.ReplaceAll(path, "\\", "/")
	path = api.ObjectPathEscape(path)
	path += "/"
	values := make(url.Values)
	values.Set("bucket", bucket)
	return
}

func (c *Client) RenameObject(ctx context.Context, bucket, oldName, newName string, isDir, force bool) (err error) {
	mode := api.ObjectsRenameModeSingle
	if isDir {
		oldName += "/"
		newName += "/"
		mode = api.ObjectsRenameModeMulti
	}
	err = c.c.WithContext(ctx).POST("/api/bus/objects/rename", api.ObjectsRenameRequest{
		Bucket: bucket,
		Force:  force,
		From:   "/" + oldName,
		To:     "/" + newName,
		Mode:   mode,
	}, nil)
	fmt.Printf("Renaming object: bucket=%s, from=%s, to=%s, isDir=%v, force=%v, err=%v\n", bucket, oldName, newName, isDir, force, err) //TODO
	return
}

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

func doRequest(req *http.Request, resp interface{}) (http.Header, int, error) {
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	defer io.Copy(io.Discard, r.Body)

	if r.StatusCode < 200 || r.StatusCode >= 300 {
		lr := io.LimitReader(r.Body, 1<<20) // 1MiB
		errMsg, _ := io.ReadAll(lr)
		return r.Header, r.StatusCode, fmt.Errorf("HTTP error: %s (status: %d)", string(errMsg), r.StatusCode)
	} else if resp != nil {
		return r.Header, r.StatusCode, json.NewDecoder(r.Body).Decode(resp)
	}

	return r.Header, r.StatusCode, nil
}
