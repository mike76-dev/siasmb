package client

import (
	"context"
	"fmt"
	"strings"

	"go.sia.tech/jape"
	"go.sia.tech/renterd/api"
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
	path = api.ObjectPathEscape(path)
	path += "?bucket=" + bucket
	err = c.c.WithContext(ctx).GET(fmt.Sprintf("/api/bus/objects/%s", path), &obj)
	return
}

func (c *Client) GetObjectInfo(ctx context.Context, bucket, path string) (info api.ObjectMetadata, err error) {
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
