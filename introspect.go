package oidc

import "fmt"

type IntrospectFlow struct {
	Config     *Config
	FlowConfig *IntrospectFlowConfig
}

type IntrospectFlowConfig struct {
	BearerToken   string
	Token         string
	TokenTypeHint string
}

func (c *IntrospectFlow) Run() error {
	c.Config.DiscoverEndpoints()

	req := IntrospectionRequest{
		Endpoint:      c.Config.IntrospectionEndpoint,
		ClientID:      c.Config.ClientID,
		ClientSecret:  c.Config.ClientSecret,
		Token:         c.FlowConfig.Token,
		TokenTypeHint: c.FlowConfig.TokenTypeHint,
		BearerToken:   c.FlowConfig.BearerToken,
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
