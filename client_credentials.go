package oidc

import (
	"context"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
)

type ClientCredentialsFlow struct {
	Config     *Config
	FlowConfig *ClientCredentialsFlowConfig
	client     *Client
}

type ClientCredentialsFlowConfig struct {
	Scopes string
}

func (c *ClientCredentialsFlow) Run(ctx context.Context) error {
	c.client = NewClient(c.Config)

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

	resp, err := req.Execute(c.Config.TokenEndpoint, c.client.http)
	if err != nil {
		return err
	}

	jsonStr, err := resp.JSON()
	if err != nil {
		return err
	}
	log.Outputf(jsonStr + "\n")
	return nil
}
