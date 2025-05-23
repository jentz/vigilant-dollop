package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
	"net/http"
)

type IntrospectFlow struct {
	Config     *Config
	FlowConfig *IntrospectFlowConfig
}

type IntrospectFlowConfig struct {
	BearerToken    string
	Token          string
	TokenTypeHint  string
	ResponseFormat string
}

func (c *IntrospectFlow) Run(ctx context.Context) error {
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
	log.Printf(jsonStr + "\n")
	return nil
}
