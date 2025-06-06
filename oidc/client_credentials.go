package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
)

type ClientCredentialsFlow struct {
	Config     *Config
	FlowConfig *ClientCredentialsFlowConfig
}

type ClientCredentialsFlowConfig struct {
	Scopes string
}

func (c *ClientCredentialsFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	req := httpclient.CreateClientCredentialsRequest(
		c.Config.ClientID,
		c.Config.ClientSecret,
		c.Config.AuthMethod,
		c.FlowConfig.Scopes,
	)

	resp, err := client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, req, nil /* no custom headers */)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		if errors.Is(err, httpclient.ErrParsingJSON) {
			return fmt.Errorf("invalid JSON response: %w", err)
		} else if errors.Is(err, httpclient.ErrOAuthError) {
			return fmt.Errorf("authorization server rejected request: %w", err)
		} else if errors.Is(err, httpclient.ErrHTTPFailure) {
			return fmt.Errorf("HTTP request failed: %w", err)
		}
		return fmt.Errorf("token error: %w", err)
	}

	// Print available response data
	if tokenData != nil {
		prettyJSON, _ := json.MarshalIndent(tokenData, "", "  ")
		log.Outputf("%s\n", string(prettyJSON))
	}
	return nil
}
