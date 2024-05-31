package main

import (
	"bytes"
	"flag"
	oidc "github.com/jentz/vigilant-dollop"
)

func parseAuthorizationCodeFlags(name string, args []string) (config oidc.Command, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	var conf oidc.AuthorizationCodeConfig
	flags.StringVar(&conf.DiscoveryEndpoint, "discovery-url", "", "set OIDC discovery url")
	flags.StringVar(&conf.AuthorizationEndpoint, "authorization-url", "", "set OIDC authorization url")
	flags.StringVar(&conf.TokenEndpoint, "token-url", "", "set OIDC token url")
	flags.StringVar(&conf.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&conf.ClientSecret, "client-secret", "", "set client secret")
	flags.StringVar(&conf.Scopes, "scopes", "", "set scopes as a space separated list")
	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	return &conf, buf.String(), nil
}
