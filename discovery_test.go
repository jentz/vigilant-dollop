package oidc

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"
)

type mockTransport func(req *http.Request) (*http.Response, error)

func (f mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

const (
	defaultBody = `{
					"issuer": "https://example.com",
					"authorization_endpoint": "https://example.com/auth",
					"token_endpoint": "https://example.com/token",
					"jwks_uri": "https://example.com/jwks"
					}`
)

func TestDiscover(t *testing.T) {
	type args struct {
		ctx          context.Context
		issuer       string
		httpClient   *http.Client
		wellKnownURL string
	}
	type httpRes struct {
		body       string
		statusCode int
	}
	tests := []struct {
		name    string
		args    args
		httpRes httpRes
		want    *DiscoveryConfiguration
		wantErr bool
		wantURL string
	}{
		{
			name: "simple",
			args: args{
				ctx:        context.Background(),
				issuer:     "https://example.com",
				httpClient: http.DefaultClient,
			},
			httpRes: httpRes{
				body:       defaultBody,
				statusCode: http.StatusOK,
			},
			want: &DiscoveryConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/auth",
				TokenEndpoint:         "https://example.com/token",
				JwksURI:               "https://example.com/jwks",
			},
			wantErr: false,
			wantURL: "https://example.com/.well-known/openid-configuration",
		},
		{
			name: "invalid issuer",
			args: args{
				ctx:        context.Background(),
				issuer:     "https://example.com",
				httpClient: http.DefaultClient,
			},
			httpRes: httpRes{
				body:       `{"issuer": "https://invalid.com"}`,
				statusCode: http.StatusOK,
			},
			want:    nil,
			wantErr: true,
			wantURL: "https://example.com/.well-known/openid-configuration",
		},
		{
			name: "override wellknown url",
			args: args{
				ctx:          context.Background(),
				issuer:       "https://example.com",
				httpClient:   http.DefaultClient,
				wellKnownURL: "https://example.com/.well-known/override",
			},
			httpRes: httpRes{
				body:       defaultBody,
				statusCode: http.StatusOK,
			},
			want: &DiscoveryConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/auth",
				TokenEndpoint:         "https://example.com/token",
				JwksURI:               "https://example.com/jwks",
			},
			wantErr: false,
			wantURL: "https://example.com/.well-known/override",
		},
		{
			name: "non 200 status code",
			args: args{
				ctx:        context.Background(),
				issuer:     "https://example.com",
				httpClient: http.DefaultClient,
			},
			httpRes: httpRes{
				body:       "expected error",
				statusCode: http.StatusNotFound,
			},
			want:    nil,
			wantErr: true,
			wantURL: "https://example.com/.well-known/openid-configuration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequest *http.Request
			tt.args.httpClient.Transport = mockTransport(func(req *http.Request) (*http.Response, error) {
				capturedRequest = req
				return &http.Response{
					StatusCode: tt.httpRes.statusCode,
					Body:       io.NopCloser(bytes.NewBufferString(tt.httpRes.body)),
				}, nil
			})
			got, err := discover(tt.args.ctx, tt.args.issuer, tt.args.httpClient, tt.args.wellKnownURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("discover() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("discover() got = %v, want %v", got, tt.want)
			}
			if capturedRequest.URL.String() != tt.wantURL {
				t.Errorf("discover() got = %v, want URL = %v", capturedRequest.URL.String(), tt.wantURL)
			}
		})
	}
}
