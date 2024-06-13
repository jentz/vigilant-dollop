package main

import (
	"bytes"
	"flag"

	oidc "github.com/jentz/vigilant-dollop"
)

func parseAuthorizationCodeFlags(name string, args []string) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	var serverConf oidc.ServerConfig
	flags.StringVar(&serverConf.IssuerUrl, "issuer", "", "set issuer url (required)")
	flags.StringVar(&serverConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&serverConf.AuthorizationEndpoint, "authorization-url", "", "override authorization url")
	flags.StringVar(&serverConf.TokenEndpoint, "token-url", "", "override token url")

	var clientConf oidc.ClientConfig
	flags.StringVar(&clientConf.ClientID, "client-id", "", "set client ID (required)")
	flags.StringVar(&clientConf.ClientSecret, "client-secret", "", "set client secret (required if not using PKCE)")

	var flowConf oidc.AuthorizationCodeFlowConfig
	flags.StringVar(&flowConf.Scopes, "scopes", "openid", "set scopes as a space separated list")
	flags.StringVar(&flowConf.CallbackURI, "callback-uri", "http://localhost:9555/callback", "set OIDC callback uri")
	flags.BoolVar(&flowConf.PKCE, "pkce", false, "use proof-key for code exchange (PKCE)")

	runner = &oidc.AuthorizationCodeFlow{
		ServerConfig: &serverConf,
		ClientConfig: &clientConf,
		FlowConfig:   &flowConf,
	}

	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	var invalidArgsChecks = []struct {
		condition bool
		message   string
	}{
		{
			(serverConf.IssuerUrl == ""),
			"issuer is required",
		},
		{
			(clientConf.ClientID == ""),
			"client-id is required",
		},
		{
			(clientConf.ClientSecret == "" && !flowConf.PKCE),
			"client-secret is required unless using PKCE",
		},
		{
			(flowConf.Scopes == ""),
			"scopes are required",
		},
		{
			(flowConf.CallbackURI == ""),
			"callback-uri is required",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, flag.ErrHelp
		}
	}

	return runner, buf.String(), nil
}
