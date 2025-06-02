package transport

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Config holds HTTP client configuration.
type Config struct {
	SkipTLSVerify bool          // Skip TLS verification for HTTP requests
	Timeout       time.Duration // Timeout for HTTP requests
}

// NewClient creates a configured HTTP client
func NewClient(cfg *Config) *http.Client {
	if cfg == nil {
		cfg = &Config{
			Timeout: 10 * time.Second,
		}
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second // Default timeout
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipTLSVerify,
			},
		},
		Timeout: cfg.Timeout,
	}
}
