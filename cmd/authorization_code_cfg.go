package main

import (
	"bytes"
	"flag"

	oidc "github.com/jentz/vigilant-dollop"
)

func parseAuthorizationCodeFlags(name string, args []string, oidcConf *oidc.Config) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerUrl, "issuer", oidcConf.IssuerUrl, "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", oidcConf.DiscoveryEndpoint, "override discovery url")
	flags.StringVar(&oidcConf.AuthorizationEndpoint, "authorization-url", "", "override authorization url")
	flags.StringVar(&oidcConf.TokenEndpoint, "token-url", "", "override token url")
	flags.StringVar(&oidcConf.ClientID, "client-id", oidcConf.ClientID, "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", oidcConf.ClientSecret, "set client secret (required if not using PKCE)")
	flags.BoolVar(&oidcConf.SkipTLSVerify, "skip-tls-verify", oidcConf.SkipTLSVerify, "skip TLS certificate verification")

	var flowConf oidc.AuthorizationCodeFlowConfig
	flags.StringVar(&flowConf.Scopes, "scopes", "openid", "set scopes as a space separated list")
	flags.StringVar(&flowConf.CallbackURI, "callback-uri", "http://localhost:9555/callback", "set OIDC redirect uri")
	flags.StringVar(&flowConf.Prompt, "prompt", "", "set prompt parameter to login, consent, select_account, or none")
	flags.StringVar(&flowConf.AcrValues, "acr-values", "", "set acr_values parameter")
	flags.StringVar(&flowConf.LoginHint, "login-hint", "", "set login_hint parameter")
	flags.StringVar(&flowConf.MaxAge, "max-age", "", "set max_age parameter")
	flags.StringVar(&flowConf.UILocales, "ui-locales", "", "set ui_locales parameter")
	flags.StringVar(&flowConf.State, "state", "", "set state parameter")
	flags.Var(&flowConf.CustomArgs, "custom", "custom authorization parameters, argument can be given multiple times")
	flags.BoolVar(&flowConf.PKCE, "pkce", false, "use proof-key for code exchange (PKCE)")
	flags.BoolVar(&flowConf.PAR, "par", false, "use pushed authorization requests")

	runner = &oidc.AuthorizationCodeFlow{
		Config:     oidcConf,
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
