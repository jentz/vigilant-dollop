package oidc

import (
	"fmt"
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
		Endpoint:     c.Config.TokenEndpoint,
		GrantType:    "client_credentials",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
	}

	if c.FlowConfig.Scopes != "" {
		req.Scope = c.FlowConfig.Scopes
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
