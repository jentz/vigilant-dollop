package oidc

import (
	"encoding/json"
	"log"
	"net/http"
)

type Config struct {
	ClientID              string
	ClientSecret          string
	IssuerUrl             string
	DiscoveryEndpoint     string
	AuthorizationEndpoint string
	TokenEndpoint         string
	IntrospectionEndpoint string
	UserinfoEndpoint      string
	JWKSEndpoint          string
}

func assignIfEmpty(a *string, b string) {
	if *a == "" {
		*a = b
	}
}

func (c *Config) DiscoverEndpoints() {
	assignIfEmpty(&c.DiscoveryEndpoint, c.IssuerUrl+"/.well-known/openid-configuration")
	resp, err := http.Get(c.DiscoveryEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	var discoveryJson map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&discoveryJson)
	assignIfEmpty(&c.AuthorizationEndpoint, discoveryJson["authorization_endpoint"].(string))
	assignIfEmpty(&c.TokenEndpoint, discoveryJson["token_endpoint"].(string))
	assignIfEmpty(&c.IntrospectionEndpoint, discoveryJson["introspection_endpoint"].(string))
	assignIfEmpty(&c.UserinfoEndpoint, discoveryJson["userinfo_endpoint"].(string))
	assignIfEmpty(&c.JWKSEndpoint, discoveryJson["jwks_uri"].(string))
}

type CustomArgs []string

func (c *CustomArgs) String() string {
	return ""
}

func (c *CustomArgs) Set(value string) error {
	*c = append(*c, value)
	return nil
}