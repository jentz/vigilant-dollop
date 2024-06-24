package oidc

import (
	"fmt"
)

type ClientCredentialsFlow struct {
	Config *Config
}

func (c *ClientCredentialsFlow) Run() error {
	c.Config.DiscoverEndpoints()

	req := TokenRequest{
		Endpoint:     c.Config.TokenEndpoint,
		GrantType:    "client_credentials",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
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
