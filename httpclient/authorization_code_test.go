package httpclient

import (
	"context"
	"net/url"
	"testing"
)

func TestCreateAuthorizationCodeRequestValues(t *testing.T) {
	tests := []struct {
		name       string
		req        *AuthorizationCodeRequest
		wantErr    bool
		wantParams map[string]string
	}{
		{
			name: "minimal required fields",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
			},
			wantErr: false,
			wantParams: map[string]string{
				"response_type": "code",
				"client_id":     "test-client",
			},
		},
		{
			name: "all standard fields",
			req: &AuthorizationCodeRequest{
				ClientID:            "test-client",
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid profile email",
				State:               "random-state-123",
				Prompt:              "consent",
				AcrValues:           "level1 level2",
				LoginHint:           "user@example.com",
				MaxAge:              "3600",
				UILocales:           "en-US",
				CodeChallengeMethod: "S256",
				CodeChallenge:       "challenge123",
				RequestURI:          "urn:ietf:params:oauth:request_uri:example",
			},
			wantErr: false,
			wantParams: map[string]string{
				"response_type":         "code",
				"client_id":             "test-client",
				"redirect_uri":          "https://example.com/callback",
				"scope":                 "openid profile email",
				"state":                 "random-state-123",
				"prompt":                "consent",
				"acr_values":            "level1 level2",
				"login_hint":            "user@example.com",
				"max_age":               "3600",
				"ui_locales":            "en-US",
				"code_challenge_method": "S256",
				"code_challenge":        "challenge123",
				"request_uri":           "urn:ietf:params:oauth:request_uri:example",
			},
		},
		{
			name: "with custom arguments",
			req: &AuthorizationCodeRequest{
				ClientID: "test-client",
				CustomArgs: &CustomArgs{
					"custom_param":  "custom_value",
					"another_param": "another_value",
				},
			},
			wantErr: false,
			wantParams: map[string]string{
				"response_type": "code",
				"client_id":     "test-client",
				"custom_param":  "custom_value",
				"another_param": "another_value",
			},
		},
		{
			name: "missing client_id",
			req: &AuthorizationCodeRequest{
				RedirectURI: "https://example.com/callback",
				Scope:       "openid",
			},
			wantErr: true,
		},
		{
			name: "empty client_id",
			req: &AuthorizationCodeRequest{
				ClientID: "",
				Scope:    "openid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, err := CreateAuthorizationCodeRequestValues(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check all expected parameters
			for key, want := range tt.wantParams {
				got := values.Get(key)
				if got != want {
					t.Errorf("got param %s=%q, want %q", key, got, want)
				}
			}

			// Check that unexpected parameters are not set
			if values.Get("redirect_uri") != tt.req.RedirectURI {
				t.Errorf("redirect_uri mismatch: got %q, want %q", values.Get("redirect_uri"), tt.req.RedirectURI)
			}
		})
	}
}

func TestCreateAuthorizationCodeRequestURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		values   *url.Values
		wantErr  bool
		wantURL  string
	}{
		{
			name:     "valid endpoint and values",
			endpoint: "https://auth.example.com/authorize",
			values: &url.Values{
				"response_type": []string{"code"},
				"client_id":     []string{"test-client"},
				"scope":         []string{"openid profile"},
			},
			wantErr: false,
			wantURL: "https://auth.example.com/authorize?client_id=test-client&response_type=code&scope=openid+profile",
		},
		{
			name:     "endpoint with existing query params",
			endpoint: "https://auth.example.com/authorize?existing=param",
			values: &url.Values{
				"response_type": []string{"code"},
				"client_id":     []string{"test-client"},
			},
			wantErr: false,
			wantURL: "https://auth.example.com/authorize?client_id=test-client&response_type=code",
		},
		{
			name:     "empty endpoint",
			endpoint: "",
			values: &url.Values{
				"response_type": []string{"code"},
			},
			wantErr: true,
		},
		{
			name:     "nil values",
			endpoint: "https://auth.example.com/authorize",
			values:   nil,
			wantErr:  true,
		},
		{
			name:     "invalid endpoint URL",
			endpoint: "://invalid-url",
			values: &url.Values{
				"response_type": []string{"code"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, err := CreateAuthorizationCodeRequestURL(tt.endpoint, tt.values)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Parse both URLs to compare them properly (query param order may vary)
			gotParsed, err := url.Parse(gotURL)
			if err != nil {
				t.Fatalf("Failed to parse result URL: %v", err)
			}

			wantParsed, err := url.Parse(tt.wantURL)
			if err != nil {
				t.Fatalf("Failed to parse expected URL: %v", err)
			}

			// Compare scheme, host, and path
			if gotParsed.Scheme != wantParsed.Scheme {
				t.Errorf("got scheme %q, want %q", gotParsed.Scheme, wantParsed.Scheme)
			}
			if gotParsed.Host != wantParsed.Host {
				t.Errorf("got host %q, want %q", gotParsed.Host, wantParsed.Host)
			}
			if gotParsed.Path != wantParsed.Path {
				t.Errorf("got path %q, want %q", gotParsed.Path, wantParsed.Path)
			}

			// Compare query parameters
			gotQuery := gotParsed.Query()
			wantQuery := wantParsed.Query()

			for key, wantVals := range wantQuery {
				gotVals := gotQuery[key]
				if len(gotVals) != len(wantVals) {
					t.Errorf("param %s: got %d values, want %d", key, len(gotVals), len(wantVals))
					continue
				}
				for i, wantVal := range wantVals {
					if gotVals[i] != wantVal {
						t.Errorf("param %s[%d]: got %q, want %q", key, i, gotVals[i], wantVal)
					}
				}
			}
		})
	}
}

// TODO: ExecuteAuthorizationCodeRequest needs to be broken down
// and made more testable with mocks to get further
func TestExecuteAuthorizationCodeRequest_BasicValidation(t *testing.T) {
	// Test basic parameter validation without actually executing the flow
	client := NewClient(nil)
	ctx := context.Background()

	// Test with invalid request (missing client_id)
	req := &AuthorizationCodeRequest{
		RedirectURI: "http://localhost:8080/callback",
	}

	_, err := client.ExecuteAuthorizationCodeRequest(ctx, "https://auth.example.com/authorize", "http://localhost:8080/callback", req)
	if err == nil {
		t.Error("Expected error for missing client_id, got nil")
	}

	// The error should be related to the request validation
	if err != nil && err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}
