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

	var oidcConf oidc.Config
	flags.StringVar(&oidcConf.IssuerUrl, "issuer", "", "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.AuthorizationEndpoint, "authorization-url", "", "override authorization url")
	flags.StringVar(&oidcConf.TokenEndpoint, "token-url", "", "override token url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret (required if not using PKCE)")

	var flowConf oidc.AuthorizationCodeFlowConfig
	flags.StringVar(&flowConf.Scopes, "scopes", "openid", "set scopes as a space separated list")
	flags.StringVar(&flowConf.CallbackURI, "callback-uri", "http://localhost:9555/callback", "set OIDC callback uri")
	flags.Var(&flowConf.CustomArgs, "custom", "custom authorization parameters (e.g. prompt=login), argument can be given multiple times")
	flags.BoolVar(&flowConf.PKCE, "pkce", false, "use proof-key for code exchange (PKCE)")

	runner = &oidc.AuthorizationCodeFlow{
		Config:     &oidcConf,
		FlowConfig: &flowConf,
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
			oidcConf.IssuerUrl == "",
			"issuer is required",
		},
		{
			oidcConf.ClientID == "",
			"client-id is required",
		},
		{
			oidcConf.ClientSecret == "" && !flowConf.PKCE,
			"client-secret is required unless using PKCE",
		},
		{
			flowConf.Scopes == "",
			"scopes are required",
		},
		{
			flowConf.CallbackURI == "",
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
