package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"reflect"

	"github.com/jentz/vigilant-dollop/pkg/crypto"
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
	PrivateKeyFile                     string
	PublicKeyFile                      string
	PrivateKey                         any
	PublicKey                          any
}

func assignIfEmpty[T any](a *T, b T) {
	if reflect.ValueOf(*a).IsZero() {
		*a = b
	}
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

func (c *Config) ReadKeyFiles() {
	// Parse the private key if provided
	if c.PrivateKeyFile != "" {
		pem, err := crypto.ReadPEMBlockFromFile(c.PrivateKeyFile)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to read private key file: %v", err))
		}
		c.PrivateKey, err = crypto.ParsePrivateKeyPEMBlock(pem)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to parse private key: %v", err))
		}
	}

	// Parse the public key if provided
	if c.PublicKeyFile != "" {
		pem, err := crypto.ReadPEMBlockFromFile(c.PublicKeyFile)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to read public key file: %v", err))
		}
		c.PublicKey, err = crypto.ParsePublicKeyPEMBlock(pem)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to parse public key: %v", err))
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
