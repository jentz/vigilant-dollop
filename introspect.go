package oidc

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

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
		ClientID:      c.Config.ClientID,
		ClientSecret:  c.Config.ClientSecret,
		Token:         c.FlowConfig.Token,
		TokenTypeHint: c.FlowConfig.TokenTypeHint,
		BearerToken:   c.FlowConfig.BearerToken,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Config.SkipTLSVerify,
			},
		},
	}

	resp, err := req.Execute(c.Config.IntrospectionEndpoint, c.Config.Verbose, client)
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
