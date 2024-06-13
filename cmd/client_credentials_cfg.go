package main

import (
	"bytes"
	"flag"

	oidc "github.com/jentz/vigilant-dollop"
)

func parseClientCredentialsFlags(name string, args []string) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	var serverConf oidc.ServerConfig
	flags.StringVar(&serverConf.IssuerUrl, "issuer", "", "set issuer url (required)")
	flags.StringVar(&serverConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&serverConf.TokenEndpoint, "token-url", "", "override token url")

	var clientConf oidc.ClientConfig
	flags.StringVar(&clientConf.ClientID, "client-id", "", "set client ID (required)")
	flags.StringVar(&clientConf.ClientSecret, "client-secret", "", "set client secret (required)")

	runner = &oidc.ClientCredentialsFlow{
		ServerConfig: &serverConf,
		ClientConfig: &clientConf,
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
			(clientConf.ClientSecret == ""),
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