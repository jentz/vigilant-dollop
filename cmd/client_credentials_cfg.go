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
	flags.StringVar(&serverConf.DiscoveryEndpoint, "discovery-url", "", "set OIDC discovery url")
	flags.StringVar(&serverConf.TokenEndpoint, "token-url", "", "set OIDC token url")

	var clientConf oidc.ClientConfig
	flags.StringVar(&clientConf.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&clientConf.ClientSecret, "client-secret", "", "set client secret")

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
			(clientConf.ClientID == ""),
			"client-id is required",
		},
		{
			(clientConf.ClientSecret == ""),
			"client-secret is required",
		},
		{
			(serverConf.DiscoveryEndpoint == "" && serverConf.TokenEndpoint == ""),
			"discovery-url or token-url are required",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, flag.ErrHelp
		}
	}

	return runner, buf.String(), nil
}