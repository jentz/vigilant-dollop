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

// discover fetches OIDC configuration from the discovery endpoint
// If wellKnownURL is provided, it will be used as the discovery endpoint
// Otherwise, the standard discovery endpoint will be used
func discover(ctx context.Context, issuer string, httpClient *http.Client, wellKnownURL string) (*DiscoveryConfiguration, error) {
	// Determine the well-known URL
	var discoveryURL string
	if wellKnownURL != "" {
		discoveryURL = wellKnownURL
	} else {
		discoveryURL = strings.TrimSuffix(issuer, "/") + DiscoveryEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	discoveryConfig := new(DiscoveryConfiguration)
	err = httpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}

	// Validate issuer - only if using standard discovery endpoint
	if wellKnownURL == "" && discoveryConfig.Issuer != issuer {
		return nil, ErrIssuerInvalid
	}

	return discoveryConfig, nil
}
