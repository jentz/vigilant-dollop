package oidc

import (
	"encoding/json"
	"log"
	"net/http"
)

type AuthorizationCodeConfig struct {
	DiscoveryEndpoint     string
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          string
	Scopes                string
}

func (c *AuthorizationCodeConfig) DiscoverEndpoints() {
	if c.DiscoveryEndpoint != "" {
		resp, err := http.Get(c.DiscoveryEndpoint)
		if err != nil {
			log.Fatal(err)
		}
		var discoveryJson map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&discoveryJson)
		c.AuthorizationEndpoint = discoveryJson["authorization_endpoint"].(string)
		c.TokenEndpoint = discoveryJson["token_endpoint"].(string)
	}
}

func (c *AuthorizationCodeConfig) Run() error {
	HandleOpenIDFlow(c.ClientID, c.ClientSecret, c.Scopes, "http://localhost:9555/callback", c.DiscoveryEndpoint, c.AuthorizationEndpoint, c.TokenEndpoint)
	return nil
}
