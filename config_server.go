package oidc

import (
	"encoding/json"
	"log"
	"net/http"
)

type ServerConfig struct {
	DiscoveryEndpoint     string
	AuthorizationEndpoint string
	TokenEndpoint         string
	IntrospectionEndpoint string
	UserinfoEndpoint      string
}

func (c *ServerConfig) DiscoverEndpoints() {
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