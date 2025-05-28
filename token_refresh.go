package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
	"net/http"
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

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Config.SkipTLSVerify,
			},
		},
	}

	resp, err := req.Execute(c.Config.TokenEndpoint, client)
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
