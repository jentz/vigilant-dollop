package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

type TokenRefreshFlow struct {
	Config     *Config
	FlowConfig *TokenRefreshFlowConfig
}

type TokenRefreshFlowConfig struct {
	Scopes       string
	RefreshToken string
}

func (c *TokenRefreshFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	req := httpclient.CreateRefreshTokenRequest(c.Config.ClientID, c.Config.ClientSecret, c.Config.AuthMethod, c.FlowConfig.RefreshToken, c.FlowConfig.Scopes)

	resp, err := client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, req, nil /* no custom headers */)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return httpclient.WrapError(err, "token")
	}

	// Print available response data
	prettyJSON, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format token response: %w", err)
	}
	log.Outputf("%s\n", string(prettyJSON))
	return nil
}
