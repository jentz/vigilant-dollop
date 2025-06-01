package main

import (
	"bytes"
	"flag"
	"github.com/jentz/oidc-cli/pkg/log"

	oidc "github.com/jentz/oidc-cli"
)

func parseGlobalFlags(name string, args []string) (oidcConf *oidc.Config, remainingArgs []string, output string, err error) {
	oidcConf = &oidc.Config{}

	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	flags.StringVar(&oidcConf.IssuerURL, "issuer", "", "set issuer url")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret")
	flags.BoolVar(&oidcConf.SkipTLSVerify, "skip-tls-verify", false, "skip TLS certificate verification")
	var verbose bool
	flags.BoolVar(&verbose, "verbose", false, "enable verbose output")

	err = flags.Parse(args)
	if err != nil {
		return nil, flags.Args(), buf.String(), err
	}

	log.SetDefaultLogger(log.WithVerbose(verbose))

	return oidcConf, flags.Args(), buf.String(), nil
}
