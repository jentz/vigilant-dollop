package main

import (
	"reflect"
	"testing"

	oidc "github.com/jentz/vigilant-dollop"
)

func TestParseIntrospectFlagsResult(t *testing.T) {

	var tests = []struct {
		name     string
		args     []string
		oidcConf oidc.Config
		flowConf oidc.IntrospectFlowConfig
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--introspection-url", "https://example.com/introspection",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--token-type", "access_token",
				"--token", "token",
			},
			oidc.Config{
				IssuerUrl:             "https://example.com",
				DiscoveryEndpoint:     "https://example.com/.well-known/openid-configuration",
				IntrospectionEndpoint: "https://example.com/introspection",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.IntrospectFlowConfig{
				BearerToken:   "",
				Token:         "token",
				TokenTypeHint: "access_token",
			},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--token", "token",
			},
			oidc.Config{
				IssuerUrl:             "https://example.com",
				DiscoveryEndpoint:     "",
				IntrospectionEndpoint: "",
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
			},
			oidc.IntrospectFlowConfig{
				BearerToken:   "",
				Token:         "token",
				TokenTypeHint: "access_token",
			},
		},
		{
			"bearer token instead of client-secret provided",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--bearer-token", "bearer",
				"--token", "token",
			},
			oidc.Config{
				IssuerUrl:             "https://example.com",
				DiscoveryEndpoint:     "",
				IntrospectionEndpoint: "",
				ClientID:              "client-id",
				ClientSecret:          "",
			},
			oidc.IntrospectFlowConfig{
				BearerToken:   "bearer",
				Token:         "token",
				TokenTypeHint: "access_token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, output, err := parseIntrospectFlags("introspect", tt.args, &oidc.Config{})
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			f, ok := runner.(*oidc.IntrospectFlow)
			if !ok {
				t.Errorf("unexpected runner type: %T", runner)
			}
			if !reflect.DeepEqual(*f.Config, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", *f.Config, tt.oidcConf)
			}
			if !reflect.DeepEqual(*f.FlowConfig, tt.flowConf) {
				t.Errorf("FlowConfig got %+v, want %+v", *f.FlowConfig, tt.flowConf)
			}
		})
	}
}

func TestParseIntrospectFlagsError(t *testing.T) {

	var tests = []struct {
		name string
		args []string
	}{
		{
			"missing issuer",
			[]string{
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
		},
		{
			"missing client-secret and bearer token",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--client-id", "client-id",
			},
		},
		{
			"missing token",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := parseIntrospectFlags("introspect", tt.args, &oidc.Config{})
			if err == nil {
				t.Errorf("err got nil, want error")
			}
			if output == "" {
				t.Errorf("output got empty, want error message")
			}
		})
	}
}
