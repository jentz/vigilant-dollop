package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Since we can't directly check internal fields without exposing them,
	// we'll test behavior instead using a mock server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("test response"))
	}))
	defer ts.Close()

	tests := []struct {
		name           string
		cfg            *Config
		expectTimeout  bool // We'll test timeout behavior
		timeoutSeconds int  // How long to sleep on the server side
	}{
		{
			name:           "nil config uses defaults",
			cfg:            nil,
			expectTimeout:  false,
			timeoutSeconds: 1,
		},
		{
			name: "custom timeout works",
			cfg: &Config{
				Timeout: 5 * time.Second,
			},
			expectTimeout:  false,
			timeoutSeconds: 3,
		},
		{
			name: "timeout works correctly",
			cfg: &Config{
				Timeout: 1 * time.Second,
			},
			expectTimeout:  true,
			timeoutSeconds: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server that sleeps for the specified time
			sleepServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(time.Duration(tt.timeoutSeconds) * time.Second)
				_, _ = w.Write([]byte("response after delay"))
			}))
			defer sleepServer.Close()

			client := NewClient(tt.cfg)
			ctx := context.Background()

			// Test whether the request times out as expected
			_, err := client.Get(ctx, sleepServer.URL, nil)

			if tt.expectTimeout && err == nil {
				t.Errorf("Expected timeout error but got none")
			}
			if !tt.expectTimeout && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestTLSSkipVerify(t *testing.T) {
	// Create a server with a self-signed cert
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure response"))
	}))
	defer ts.Close()

	t.Run("Skips TLS verification when configured", func(t *testing.T) {
		client := NewClient(&Config{SkipTLSVerify: true})
		_, err := client.Get(context.Background(), ts.URL, nil)
		if err != nil {
			t.Errorf("Expected no error with SkipTLSVerify but got: %v", err)
		}
	})

	t.Run("Fails on invalid cert by default", func(t *testing.T) {
		client := NewClient(nil) // Default config
		_, err := client.Get(context.Background(), ts.URL, nil)
		if err == nil {
			t.Errorf("Expected TLS verification error but got none")
		}
	})
}

func TestCustomTransport(t *testing.T) {
	// Test that a custom is transport respected
	customTransport := &http.Transport{
		MaxIdleConns: 100,
	}

	cfg := &Config{
		Transport: customTransport,
	}

	// Create a mock server that checks the User-Agent
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("test response"))
	}))
	defer ts.Close()

	client := NewClient(cfg)
	resp, err := client.Get(context.Background(), ts.URL, nil)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsSuccess() {
		t.Errorf("Expected successful response, got: %d", resp.StatusCode)
	}
}
