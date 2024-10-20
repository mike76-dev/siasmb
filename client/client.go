package client

import (
	"fmt"

	"go.sia.tech/jape"
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

type Bucket struct {
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

func (c *Client) GetBucket(name string) (bucket Bucket, err error) {
	err = c.c.GET(fmt.Sprintf("/api/bus/bucket/%s", name), &bucket)
	return
}
