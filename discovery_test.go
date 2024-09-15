package oidc

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func Test_discover(t *testing.T) {
	type args struct {
		ctx          context.Context
		issuer       string
		httpClient   *http.Client
		wellKnownUrl []string
	}
	tests := []struct {
		name               string
		args               args
		want               *DiscoveryConfiguration
		wantErr            bool
		expectedBody       string
		expectedStatusCode int
		expectedURL        string
	}{
		{
			name: "simple",
			args: args{
				ctx:        context.Background(),
				issuer:     "https://example.com",
				httpClient: http.DefaultClient,
			},
			want: &DiscoveryConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/auth",
				TokenEndpoint:         "https://example.com/token",
				JwksURI:               "https://example.com/jwks",
			},
			wantErr: false,
			expectedBody: `{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/jwks"
			}`,
			expectedStatusCode: http.StatusOK,
			expectedURL:        "https://example.com/.well-known/openid-configuration",
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:        context.Background(),
				issuer:     "https://example.com",
				httpClient: http.DefaultClient,
			},
			want:               nil,
			wantErr:            true,
			expectedBody:       `{"issuer": "https://invalid.com"}`,
			expectedStatusCode: http.StatusOK,
			expectedURL:        "https://example.com/.well-known/openid-configuration",
		},
		{
			name: "override wellknown url",
			args: args{
				ctx:          context.Background(),
				issuer:       "https://example.com",
				httpClient:   http.DefaultClient,
				wellKnownUrl: []string{"https://example.com/.well-known/override"},
			},
			want: &DiscoveryConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/auth",
				TokenEndpoint:         "https://example.com/token",
				JwksURI:               "https://example.com/jwks",
			},
			wantErr: false,
			expectedBody: `{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/jwks"
			}`,
			expectedStatusCode: http.StatusOK,
			expectedURL:        "https://example.com/.well-known/override",
		},
		{
			name: "non 200 status code",
			args: args{
				ctx:        context.Background(),
				issuer:     "https://example.com",
				httpClient: http.DefaultClient,
			},
			want:               nil,
			wantErr:            true,
			expectedBody:       `expected error`,
			expectedStatusCode: http.StatusNotFound,
			expectedURL:        "https://example.com/.well-known/openid-configuration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequest *http.Request
			tt.args.httpClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				capturedRequest = req
				return &http.Response{
					StatusCode: tt.expectedStatusCode,
					Body:       io.NopCloser(bytes.NewBufferString(tt.expectedBody)),
				}, nil
			})
			got, err := discover(tt.args.ctx, tt.args.issuer, tt.args.httpClient, tt.args.wellKnownUrl...)
			if (err != nil) != tt.wantErr {
				t.Errorf("discover() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("discover() got = %v, want %v", got, tt.want)
			}
			if capturedRequest.URL.String() != tt.expectedURL {
				t.Errorf("expected URL = %v, got %v", tt.expectedURL, capturedRequest.URL.String())
			}
		})
	}
}
