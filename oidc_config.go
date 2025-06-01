package oidc

import (
	"context"
	"fmt"
	"github.com/jentz/oidc-cli/pkg/crypto"
)

type AuthMethodValue string

const (
	AuthMethodClientSecretBasic AuthMethodValue = "client_secret_basic"
	AuthMethodClientSecretPost  AuthMethodValue = "client_secret_post"
)

var validAuthMethods = map[AuthMethodValue]bool{
	AuthMethodClientSecretBasic: true,
	AuthMethodClientSecretPost:  true,
}

func (a *AuthMethodValue) Set(value string) error {
	methodValue := AuthMethodValue(value)
	if !methodValue.IsValid() {
		return fmt.Errorf("invalid auth method %q, valid values are: %s, %s",
			value, AuthMethodClientSecretBasic, AuthMethodClientSecretPost)
	}
	*a = methodValue
	return nil
}

func (a *AuthMethodValue) String() string {
	return string(*a)
}

func (a *AuthMethodValue) IsValid() bool {
	return validAuthMethods[*a]
}

type Config struct {
	ClientID                           string
	ClientSecret                       string
	IssuerURL                          string
	DiscoveryEndpoint                  string
	AuthorizationEndpoint              string
	PushedAuthorizationRequestEndpoint string
	TokenEndpoint                      string
	IntrospectionEndpoint              string
	UserinfoEndpoint                   string
	JWKSEndpoint                       string
	SkipTLSVerify                      bool
	AuthMethod                         AuthMethodValue
	PrivateKeyFile                     string
	PublicKeyFile                      string
	PrivateKey                         any
	PublicKey                          any
}

func (c *Config) DiscoverEndpoints(ctx context.Context) error {
	client := NewClient(c)

	discoveryConfig, err := client.Discover(ctx)
	if err != nil {
		return fmt.Errorf("endpoint discovery failed: %w", err)
	}

	// Set endpoints from discovery config if not already set by user
	if c.AuthorizationEndpoint == "" {
		c.AuthorizationEndpoint = discoveryConfig.AuthorizationEndpoint
	}

	if c.PushedAuthorizationRequestEndpoint == "" {
		c.PushedAuthorizationRequestEndpoint = discoveryConfig.PushedAuthorizationRequestEndpoint
	}

	if c.TokenEndpoint == "" {
		c.TokenEndpoint = discoveryConfig.TokenEndpoint
	}

	if c.IntrospectionEndpoint == "" {
		c.IntrospectionEndpoint = discoveryConfig.IntrospectionEndpoint
	}

	if c.UserinfoEndpoint == "" {
		c.UserinfoEndpoint = discoveryConfig.UserinfoEndpoint
	}

	if c.JWKSEndpoint == "" {
		c.JWKSEndpoint = discoveryConfig.JwksURI
	}

	// set default auth method if not set by user
	if c.AuthMethod == "" {
		for _, method := range discoveryConfig.TokenEndpointAuthMethods {
			authMethodValue := AuthMethodValue(method)
			if authMethodValue.IsValid() {
				c.AuthMethod = authMethodValue
				break
			}
		}
	}

	return nil
}

func (c *Config) ReadKeyFiles() error {
	// Parse the private key if provided
	if c.PrivateKeyFile != "" {
		pem, err := crypto.ReadPEMBlockFromFile(c.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("could not read private key file: %w", err)
		}
		c.PrivateKey, err = crypto.ParsePrivateKeyPEMBlock(pem)
		if err != nil {
			return fmt.Errorf("could not parse private key: %w", err)
		}
	}

	// Parse the public key if provided
	if c.PublicKeyFile != "" {
		pem, err := crypto.ReadPEMBlockFromFile(c.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %v", err)
		}
		c.PublicKey, err = crypto.ParsePublicKeyPEMBlock(pem)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}
	}
	return nil
}

type CustomArgs []string

func (c *CustomArgs) String() string {
	return ""
}

func (c *CustomArgs) Set(value string) error {
	*c = append(*c, value)
	return nil
}
