package oidc

import (
	"context"
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
	ctx := context.Background()
	discoveryConfig, err := discover(ctx, c.IssuerUrl, http.DefaultClient, c.DiscoveryEndpoint)

	if err != nil {
		log.Fatal(err)
	}

	assignIfEmpty(&c.AuthorizationEndpoint, discoveryConfig.AuthorizationEndpoint)
	assignIfEmpty(&c.TokenEndpoint, discoveryConfig.TokenEndpoint)
	assignIfEmpty(&c.IntrospectionEndpoint, discoveryConfig.IntrospectionEndpoint)
	assignIfEmpty(&c.UserinfoEndpoint, discoveryConfig.UserinfoEndpoint)
	assignIfEmpty(&c.JWKSEndpoint, discoveryConfig.JwksURI)
}

type CustomArgs []string

func (c *CustomArgs) String() string {
	return ""
}

func (c *CustomArgs) Set(value string) error {
	*c = append(*c, value)
	return nil
}
