package oidc

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
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

func (c *IntrospectFlow) Run() error {
	c.Config.DiscoverEndpoints()

	iReq := NewIntrospectionRequest(c.FlowConfig.Token, c.Config.IntrospectionEndpoint).
		WithTokenTypeHint(c.FlowConfig.TokenTypeHint).
		WithResponseFormat(c.FlowConfig.ResponseFormat)

	if c.FlowConfig.BearerToken != "" {
		iReq = iReq.WithBearerToken(c.FlowConfig.BearerToken)
	} else {
		iReq = iReq.
			WithCredentials(c.Config.ClientID, c.Config.ClientSecret).
			WithAuthMethod(c.Config.AuthMethod)
	}

	req, err := iReq.ToHttpRequest()
	if err != nil {
		return err
	}

	if c.Config.Verbose {
		fmt.Fprintf(os.Stderr, "introspection endpoint: %s\n", c.Config.IntrospectionEndpoint)

		payload, err := iReq.MaskedPayload()
		if err != nil {
			return err
		}

		if len(payload) > 0 {
			fmt.Fprintf(os.Stderr, "introspection request body: %s\n", payload.Encode())
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Config.SkipTLSVerify,
			},
		},
	}

	resp := new(IntrospectionResponse)
	err = httpRequest(client, req, &resp)
	if err != nil {
		return fmt.Errorf("failed to execute introspection request: %w", err)
	}

	jsonStr, err := resp.JSON()
	if err != nil {
		return err
	}
	fmt.Println(jsonStr)
	return nil
}
