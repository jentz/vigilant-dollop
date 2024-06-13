package main

import (
	"reflect"
	"testing"

	oidc "github.com/jentz/vigilant-dollop"
)

func TestParseClientCredentialsFlagsResult(t *testing.T) {
	
	var tests = []struct {
		name string
		args []string
		serverConf oidc.ServerConfig
		clientConf oidc.ClientConfig
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--token-url", "https://example.com/token",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.ServerConfig{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				TokenEndpoint: "https://example.com/token",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.ServerConfig{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
		},
		{
			"no scopes provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.ServerConfig{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
		},
	}
		
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseClientCredentialsFlags("client_credentials", tt.args)
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.ClientCredentialsFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
			}
			if !reflect.DeepEqual(*f.ServerConfig, tt.serverConf) {
				t.Errorf("ServerConfig got %+v, want %+v", *f.ServerConfig, tt.serverConf)
			}
			if !reflect.DeepEqual(*f.ClientConfig, tt.clientConf) {
				t.Errorf("ClientConfig got %+v, want %+v", *f.ClientConfig, tt.clientConf)
			}
		})
	}
}

func TestParseClientCredentialsFlagsError(t *testing.T) {
	
	var tests = []struct {
		name string
		args []string
	}{
		{
			"missing discovery-url and token-url",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
		},
		{
			"missing client-secret",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
			},
		},
	}
		
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseClientCredentialsFlags("client_credentials", tt.args)
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
		})
	}
}