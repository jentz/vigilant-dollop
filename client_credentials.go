package oidc

import (
	"context"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
)

type ClientCredentialsFlow struct {
	Config     *Config
	FlowConfig *ClientCredentialsFlowConfig
}

type ClientCredentialsFlowConfig struct {
	Scopes string
}

func (c *ClientCredentialsFlow) Run(ctx context.Context) error {
	err := c.Config.DiscoverEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("endpoint discovery failed: %w", err)
	}

	req := TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		AuthMethod:   c.Config.AuthMethod,
	}

	if c.FlowConfig.Scopes != "" {
		req.Scope = c.FlowConfig.Scopes
	}

	client := c.Config.newHTTPClient()

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
