package oidc

import (
	"github.com/jentz/vigilant-dollop/pkg/transport"
	"net/http"
	"time"
)

type Client struct {
	config *Config
	http   *http.Client
}

func NewClient(config *Config) *Client {
	httpConfig := &transport.Config{
		SkipTLSVerify: config.SkipTLSVerify,
		Timeout:       10 & time.Second,
	}

	return &Client{
		config: config,
		http:   transport.NewClient(httpConfig),
	}
}
