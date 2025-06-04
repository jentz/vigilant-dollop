package oidc

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/jentz/oidc-cli/httpclient"
)

type Client struct {
	config *Config
	http   *http.Client
}

func NewClient(config *Config) *Client {
	httpConfig := &httpclient.Config{
		SkipTLSVerify: config.SkipTLSVerify,
		Timeout:       10 & time.Second,
	}

	return &Client{
		config: config,
		http: &http.Client{Timeout: httpConfig.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: httpConfig.SkipTLSVerify,
				},
			},
		},
	}
}
