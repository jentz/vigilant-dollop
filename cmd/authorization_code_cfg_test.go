package main

import (
	"reflect"
	"testing"

	oidc "github.com/jentz/vigilant-dollop"
)

func TestParseAuthorizationCodeFlagsResult(t *testing.T) {
	
	var tests = []struct {
		name string
		args []string
		oidcConf oidc.Config
		scopes string
		callbackURI string
		pkce bool
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--authorization-url", "https://example.com/authorize",
				"--token-url", "https://example.com/token",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				AuthorizationEndpoint: "https://example.com/authorize",
				TokenEndpoint: "https://example.com/token",
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:8080/callback",
			false,
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:8080/callback",
			false,
		},
		{
			"no scopes provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid",
			"http://localhost:8080/callback",
			false,
		},
		{
			"no callback-uri provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:9555/callback",
			false,
		},
		{
			"client-secret and pkce",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--pkce", 
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid profile email",
			"http://localhost:9555/callback",
			true,
		},
		{
			"no client-secret and pkce",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--scopes", "openid profile email",
				"--pkce",
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
				ClientID: "client-id",
				ClientSecret: "",
			},
			"openid profile email",
			"http://localhost:9555/callback",
			true,
		},
		{
			"flags after non-flag argument",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"non-flag-argument",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
			oidc.Config{
				IssuerUrl: "https://example.com",
				DiscoveryEndpoint: "",
				AuthorizationEndpoint: "",
				TokenEndpoint: "",
				ClientID: "client-id",
				ClientSecret: "client-secret",
			},
			"openid", // expecting default value as argument is not parsed
			"http://localhost:9555/callback", // expecting default value as argument is not parsed
			false,
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
			if !reflect.DeepEqual(*f.Config, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", *f.Config, tt.oidcConf)
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
			"missing issuer",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--scopes", "openid profile email",
				"--callback-uri", "http://localhost:8080/callback",
			},
		},
		{
			"missing client-secret and pkce",
			[]string{
				"--issuer", "https://example.com",
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