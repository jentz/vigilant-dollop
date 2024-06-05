package main

import (
	"reflect"
	"testing"

	oidc "github.com/jentz/vigilant-dollop"
)

func TestParseAuthorizationCodeFlagsCorrect(t *testing.T) {
	
	var tests = []struct {
		name string
		args []string
		serverConf oidc.ServerConfig
		clientConf oidc.ClientConfig
		scopes string
		callbackURI string
	}{
		{
			"all flags",
			[]string{
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--authorization-url", "https://example.com/authorize",
				"--token-url", "https://example.com/token",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.ServerConfig{
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				AuthorizationEndpoint: "https://example.com/authorize",
				TokenEndpoint: "https://example.com/token",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:8080/callback",
		},
		{
			"only discovery-url",
			[]string{
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.ServerConfig{
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:8080/callback",
		},
		{
			"no scopes provided",
			[]string{
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.ServerConfig{
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid",
			"http://localhost:8080/callback",
		},
		{
			"no callback-uri provided",
			[]string{
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
			},
			oidc.ServerConfig{
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
			},
			oidc.ClientConfig{
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:9555/callback",
		},
	}
		
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseAuthorizationCodeFlags("authorization_code", tt.args)
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.AuthorizationCodeFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
			}
			if !reflect.DeepEqual(*f.ServerConfig, tt.serverConf) {
				t.Errorf("ServerConfig got %+v, want %+v", *f.ServerConfig, tt.serverConf)
			}
			if !reflect.DeepEqual(*f.ClientConfig, tt.clientConf) {
				t.Errorf("ClientConfig got %+v, want %+v", *f.ClientConfig, tt.clientConf)
			}
			if f.FlowConfig.Scopes != tt.scopes {
				t.Errorf("Scopes got %q, want %q", f.FlowConfig.Scopes, tt.scopes)
			}
			if f.FlowConfig.CallbackURI != tt.callbackURI {
				t.Errorf("CallbackURI got %q, want %q", f.FlowConfig.CallbackURI, tt.callbackURI)
			}
		})
	}
}

func TestParseAuthorizationCodeFlagsError(t *testing.T) {
	
	var tests = []struct {
		name string
		args []string
	}{
		{
			"missing discovery-url, authorization-url and token-url",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
		},
		{
			"missing client-secret",
			[]string{
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
		},
	}
		
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseAuthorizationCodeFlags("authorization_code", tt.args)
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
		})
	}
}