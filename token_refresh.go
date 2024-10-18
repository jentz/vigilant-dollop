package oidc

import "fmt"

type TokenRefreshFlow struct {
	Config     *Config
	FlowConfig *TokenRefreshFlowConfig
}

type TokenRefreshFlowConfig struct {
	RefreshToken string
}

func (c *TokenRefreshFlow) Run() error {
	c.Config.DiscoverEndpoints()

	req := TokenRequest{
		Endpoint:     c.Config.TokenEndpoint,
		GrantType:    "refresh_token",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		RefreshToken: c.FlowConfig.RefreshToken,
	}

	resp, err := req.Execute()
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
