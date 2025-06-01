package oidc

import (
	"context"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
)

type TokenRefreshFlow struct {
	Config     *Config
	FlowConfig *TokenRefreshFlowConfig
	client     *Client
}

type TokenRefreshFlowConfig struct {
	Scopes       string
	RefreshToken string
}

func (c *TokenRefreshFlow) Run(ctx context.Context) error {
	c.client = NewClient(c.Config)

	err := c.Config.DiscoverEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("failed to discover endpoints: %w", err)
	}

	req := TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		Scope:        c.FlowConfig.Scopes,
		RefreshToken: c.FlowConfig.RefreshToken,
		AuthMethod:   c.Config.AuthMethod,
	}

	resp, err := req.Execute(ctx, c.Config.TokenEndpoint, c.client.http)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	jsonStr, err := resp.JSON()
	if err != nil {
		return fmt.Errorf("failed to marshal token response: %w", err)
	}
	log.Outputf(jsonStr + "\n")
	return nil
}
