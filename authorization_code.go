package oidc

type AuthorizationCodeConfig struct {
	DiscoveryEndpoint     string
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          string
	Scopes                string
}

func (c *AuthorizationCodeConfig) Run() error {
	HandleOpenIDFlow(c.ClientID, c.ClientSecret, c.Scopes, "http://localhost:9555/callback", c.DiscoveryEndpoint, c.AuthorizationEndpoint, c.TokenEndpoint)
	return nil
}
