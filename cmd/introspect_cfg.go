package main

import (
	"bytes"
	"flag"

	oidc "github.com/jentz/vigilant-dollop"
)

func parseIntrospectFlags(name string, args []string) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	var oidcConf oidc.Config
	flags.StringVar(&oidcConf.IssuerUrl, "issuer", "", "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.IntrospectionEndpoint, "token-url", "", "override token url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret (required unless bearer token is provided)")

	var flowConf oidc.IntrospectFlowConfig
	flags.StringVar(&flowConf.BearerToken, "bearer-token", "", "bearer token for authorization (required unless client secret is provided)")
	flags.StringVar(&flowConf.Token, "token", "", "token to be introspected (required)")
	flags.StringVar(&flowConf.TokenTypeHint, "token-type", "access_token", "token type hint (e.g. access_token")

	runner = &oidc.IntrospectFlow{
		Config: &oidcConf,
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
			(oidcConf.IssuerUrl == ""),
			"issuer is required",
		},
		{
			(oidcConf.ClientID == ""),
			"client-id is required",
		},
		{
			(oidcConf.ClientSecret == ""),
			"client-secret is required",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, flag.ErrHelp
		}
	}

	return runner, buf.String(), nil
}