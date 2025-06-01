package oidc

import (
	"context"
	"fmt"
	"github.com/jentz/oidc-cli/pkg/log"
)

type IntrospectFlow struct {
	Config     *Config
	FlowConfig *IntrospectFlowConfig
	client     *Client
}

type IntrospectFlowConfig struct {
	BearerToken    string
	Token          string
	TokenTypeHint  string
	ResponseFormat string
}

func (c *IntrospectFlow) Run(ctx context.Context) error {
	c.client = NewClient(c.Config)

	err := c.Config.DiscoverEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("endpoint discpvery failed: %w", err)
	}

	req := IntrospectionRequest{
		ClientID:       c.Config.ClientID,
		ClientSecret:   c.Config.ClientSecret,
		Token:          c.FlowConfig.Token,
		TokenTypeHint:  c.FlowConfig.TokenTypeHint,
		BearerToken:    c.FlowConfig.BearerToken,
		ResponseFormat: c.FlowConfig.ResponseFormat,
		AuthMethod:     c.Config.AuthMethod,
	}

	resp, err := req.Execute(ctx, c.Config.IntrospectionEndpoint, c.client.http)
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
