package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"reflect"
)

type AuthMethodValue string

const (
	AuthMethodClientSecretBasic AuthMethodValue = "client_secret_basic"
	AuthMethodClientSecretPost  AuthMethodValue = "client_secret_post"
)

func (a *AuthMethodValue) Set(value string) error {
	if !AuthMethodValue(value).IsValid() {
		return fmt.Errorf("invalid auth method, valid values are %s", []AuthMethodValue{AuthMethodClientSecretBasic, AuthMethodClientSecretPost})
	}
	*a = AuthMethodValue(value)
	return nil
}

func (a *AuthMethodValue) String() string {
	return string(*a)
}

func (a AuthMethodValue) IsValid() bool {
	return a == AuthMethodClientSecretBasic || a == AuthMethodClientSecretPost
}

func SupportedIntrospectionResponseFormats() []string {
	// supported formats are:
	// json - default format per RFC 7662
	// jwt - defined in RFC 7519
	// token-introspection+jwt - defined in RFC 9701
	return []string{"json", "jwt", "token-introspection+jwt"}
}

func SupportedIntrospectionTokenTypeHints() []string {
	return []string{"access_token", "refresh_token"}
}

func SupportedIntrospectionAuthMethods() []AuthMethodValue {
	return []AuthMethodValue{AuthMethodClientSecretBasic, AuthMethodClientSecretPost}
}

type Config struct {
	ClientID                           string
	ClientSecret                       string
	IssuerUrl                          string
	DiscoveryEndpoint                  string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	IntrospectionEndpoint              string
	UserinfoEndpoint                   string
	JWKSEndpoint                       string
	SkipTLSVerify                      bool
	Verbose                            bool
	AuthMethod                         AuthMethodValue
}

func assignIfEmpty[T any](a *T, b T) {
	if reflect.ValueOf(*a).IsZero() {
		*a = b
	}
}

func contains[T comparable](slice []T, value T) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func (c *Config) DiscoverEndpoints() {
	ctx := context.Background()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.SkipTLSVerify,
			},
		},
	}
	discoveryConfig, err := discover(ctx, c.IssuerUrl, client, c.DiscoveryEndpoint)

	if err != nil {
		log.Fatal(err)
	}

	assignIfEmpty(&c.AuthorizationEndpoint, discoveryConfig.AuthorizationEndpoint)
	assignIfEmpty(&c.PushedAuthorizationRequestEndpoint, discoveryConfig.PushedAuthorizationRequestEndpoint)
	assignIfEmpty(&c.TokenEndpoint, discoveryConfig.TokenEndpoint)
	assignIfEmpty(&c.IntrospectionEndpoint, discoveryConfig.IntrospectionEndpoint)
	assignIfEmpty(&c.UserinfoEndpoint, discoveryConfig.UserinfoEndpoint)
	assignIfEmpty(&c.JWKSEndpoint, discoveryConfig.JwksURI)

	// use first supported auth method unless set through flag
	for _, method := range discoveryConfig.TokenEndpointAuthMethods {
		if AuthMethodValue(method).IsValid() {
			assignIfEmpty(&c.AuthMethod, AuthMethodValue(method))
			break
		}
	}
}

type CustomArgs []string

func (c *CustomArgs) String() string {
	return ""
}

func (c *CustomArgs) Set(value string) error {
	*c = append(*c, value)
	return nil
}
