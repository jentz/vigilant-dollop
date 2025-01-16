package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

type DiscoveryConfiguration struct {
	Issuer                             string   `json:"issuer,omitempty"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint,omitempty"`
	TokenEndpoint                      string   `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint              string   `json:"introspection_endpoint,omitempty"`
	UserinfoEndpoint                   string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint                 string   `json:"revocation_endpoint,omitempty"`
	DeviceAuthorizationEndpoint        string   `json:"device_authorization_endpoint,omitempty"`
	JwksURI                            string   `json:"jwks_uri,omitempty"`
	TokenEndpointAuthMethods           []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

func discover(ctx context.Context, issuer string, httpClient *http.Client, wellKnownUrl ...string) (*DiscoveryConfiguration, error) {

	wellKnown := strings.TrimSuffix(issuer, "/") + DiscoveryEndpoint
	if len(wellKnownUrl) == 1 && wellKnownUrl[0] != "" {
		wellKnown = wellKnownUrl[0]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	discoveryConfig := new(DiscoveryConfiguration)
	err = httpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		// add error context
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}
	if discoveryConfig.Issuer != issuer {
		return nil, ErrIssuerInvalid
	}
	return discoveryConfig, nil
}
