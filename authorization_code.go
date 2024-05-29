package oidc

type AuthorizationCodeConfig struct {
	DiscoveryEndpoint     string
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          string
	Scopes                string
}

type AuthorizationCodeCmd struct {
	config *AuthorizationCodeConfig
}

func NewAuthorizationCodeCmd(config *AuthorizationCodeConfig) *AuthorizationCodeCmd {
	return &AuthorizationCodeCmd{config: config}
}

func (c *AuthorizationCodeCmd) Run() error {
	HandleOpenIDFlow(c.config.ClientID, c.config.ClientSecret, c.config.Scopes, "http://localhost:9555/callback", c.config.DiscoveryEndpoint, c.config.AuthorizationEndpoint, c.config.TokenEndpoint)
	return nil
}
