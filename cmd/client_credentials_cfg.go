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

	runner = oidc.NewClientCredentialsFlow(
		&serverConf,
		&clientConf)

	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	serverConf.DiscoverEndpoints()

	return runner, buf.String(), nil
}