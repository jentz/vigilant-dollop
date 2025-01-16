package main

import (
	"reflect"
	"testing"

	oidc "github.com/jentz/vigilant-dollop"
)

func TestParseGlobalFlagsResult(t *testing.T) {

	var tests = []struct {
		name          string
		args          []string
		oidcConf      oidc.Config
		remainingArgs []string
	}{
		{
			"all flags",
			[]string{
				"--issuer", "https://example.com",
				"--discovery-url", "https://example.com/.well-known/openid-configuration",
				"--skip-tls-verify",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.Config{
				IssuerUrl:         "https://example.com",
				DiscoveryEndpoint: "https://example.com/.well-known/openid-configuration",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				SkipTLSVerify:     true,
				Verbose:           false,
			},
			[]string{},
		},
		{
			"only issuer",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
			},
			oidc.Config{
				IssuerUrl:         "https://example.com",
				DiscoveryEndpoint: "",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				Verbose:           false,
			},
			[]string{},
		},
		{
			"verbose flag",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"--verbose",
			},
			oidc.Config{
				IssuerUrl:         "https://example.com",
				DiscoveryEndpoint: "",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				Verbose:           true,
			},
			[]string{},
		},
		{
			"flags after non-flag argument",
			[]string{
				"--issuer", "https://example.com",
				"--client-id", "client-id",
				"--client-secret", "client-secret",
				"non-flag-argument",
				"--skip-tls-verify",
			},
			oidc.Config{
				IssuerUrl:         "https://example.com",
				DiscoveryEndpoint: "",
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				SkipTLSVerify:     false, // expecting default value as argument is not parsed
				Verbose:           false,
			},
			[]string{"non-flag-argument", "--skip-tls-verify"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidcConf, remainingArgs, output, err := parseGlobalFlags("global", tt.args)
			if err != nil {
				t.Errorf("err got %v, want nil", err)
			}
			if output != "" {
				t.Errorf("output got %q, want empty", output)
			}
			if !reflect.DeepEqual(*oidcConf, tt.oidcConf) {
				t.Errorf("Config got %+v, want %+v", *oidcConf, tt.oidcConf)
			}
			if !reflect.DeepEqual(remainingArgs, tt.remainingArgs) {
				t.Errorf("remainingArgs got %v, want %v", remainingArgs, tt.remainingArgs)
			}
		})
	}
}
