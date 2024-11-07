package oidc

import (
	"crypto/tls"
	"fmt"
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

func (c *TokenRefreshFlow) Run() error {
	c.Config.DiscoverEndpoints()

	req := TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		Scope:        c.FlowConfig.Scopes,
		RefreshToken: c.FlowConfig.RefreshToken,
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
	fmt.Println(jsonStr)
	return nil
}
