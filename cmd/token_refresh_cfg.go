package main

import (
	"bufio"
	"bytes"
	"flag"
	"os"

	oidc "github.com/jentz/vigilant-dollop"
)

func parseTokenRefreshFlags(name string, args []string) (runner CommandRunner, output string, err error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	var oidcConf oidc.Config
	flags.StringVar(&oidcConf.IssuerUrl, "issuer", "", "set issuer url (required)")
	flags.StringVar(&oidcConf.DiscoveryEndpoint, "discovery-url", "", "override discovery url")
	flags.StringVar(&oidcConf.IntrospectionEndpoint, "introspection-url", "", "override introspection url")
	flags.StringVar(&oidcConf.ClientID, "client-id", "", "set client ID (required)")
	flags.StringVar(&oidcConf.ClientSecret, "client-secret", "", "set client secret (required unless bearer token is provided)")

	var flowConf oidc.TokenRefreshFlowConfig
	flags.StringVar(&flowConf.RefreshToken, "refresh-token", "", "refresh token to be used for token refresh")

	runner = &oidc.TokenRefreshFlow{
		Config:     &oidcConf,
		FlowConfig: &flowConf,
	}

	err = flags.Parse(args)
	if err != nil {
		return nil, buf.String(), err
	}

	// Read refresh token from stdin if token equals '-'
	if flowConf.RefreshToken == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		flowConf.RefreshToken = scanner.Text()
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
			oidcConf.ClientSecret == "",
			"client-secret or bearer-token is required",
		},
		{
			flowConf.RefreshToken == "",
			"refresh token is required",
		},
	}

	for _, check := range invalidArgsChecks {
		if check.condition {
			return nil, check.message, flag.ErrHelp
		}
	}

	return runner, buf.String(), nil
}
