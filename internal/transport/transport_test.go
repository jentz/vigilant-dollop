package transport

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want *http.Client
	}{
		{
			name: "nil config uses defaults",
			cfg:  nil,
			want: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: false,
					},
				},
				Timeout: 10 * time.Second,
			},
		},
		{
			name: "custom config",
			cfg: &Config{
				SkipTLSVerify: true,
				Timeout:       5 * time.Second,
			},
			want: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 5 * time.Second,
			},
		},
		{
			name: "zero timeout uses default",
			cfg: &Config{
				SkipTLSVerify: true,
				Timeout:       0,
			},
			want: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 10 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewClient(tt.cfg)

			if got.Timeout != tt.want.Timeout {
				t.Errorf("NewClient() Timeout = %v, want %v", got.Timeout, tt.want.Timeout)
			}

			gotTransport, ok := got.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("NewClient() Transport is not a *http.Transport")
			}

			if gotTransport.TLSClientConfig.InsecureSkipVerify != tt.want.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
				t.Errorf("NewClient() InsecureSkipVerify = %v, want %v", gotTransport.TLSClientConfig.InsecureSkipVerify, tt.want.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify)
			}
		})
	}
}
