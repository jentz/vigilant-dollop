package oidc

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	req, err := NewIntrospectionRequestBuilder().
		SetClientID(c.Config.ClientID).
		SetClientSecret(c.Config.ClientSecret).
		SetToken(c.FlowConfig.Token).
		SetTokenTypeHint(c.FlowConfig.TokenTypeHint).
		SetBearerToken(c.FlowConfig.BearerToken).
		SetResponseFormat(c.FlowConfig.ResponseFormat).
		SetAuthMethod(c.Config.AuthMethod).
		SetEndpoint(c.Config.IntrospectionEndpoint).
		Build()

	if err != nil {
		return err
	}

	if c.Config.Verbose {
		fmt.Fprintf(os.Stderr, "introspection endpoint: %s\n", c.Config.IntrospectionEndpoint)
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()

		bodyValues, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			return fmt.Errorf("failed to parse request body: %w", err)
		}

		for k, v := range bodyValues {
			if k == "client_secret" {
				bodyValues.Set(k, "*****")
			} else {
				bodyValues[k] = v
			}
		}
		if len(bodyValues) > 0 {
			fmt.Fprintf(os.Stderr, "introspection request body: %s\n", bodyValues.Encode())
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
