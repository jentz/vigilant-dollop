package oidc

import (
	"crypto/tls"
	"github.com/jentz/vigilant-dollop/pkg/log"
	"net/http"
)

type ClientCredentialsFlow struct {
	Config     *Config
	FlowConfig *ClientCredentialsFlowConfig
}

type ClientCredentialsFlowConfig struct {
	Scopes string
}

func (c *ClientCredentialsFlow) Run() error {
	c.Config.DiscoverEndpoints()

	req := TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		AuthMethod:   c.Config.AuthMethod,
	}

	if c.FlowConfig.Scopes != "" {
		req.Scope = c.FlowConfig.Scopes
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Config.SkipTLSVerify,
			},
		},
	}

	resp, err := req.Execute(c.Config.TokenEndpoint, c.Config.Verbose, client)
	if err != nil {
		return err
	}

	jsonStr, err := resp.JSON()
	if err != nil {
		return err
	}
	log.Printf(jsonStr + "\n")
	return nil
}
