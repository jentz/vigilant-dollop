package oidc

type AuthorizationCodeFlow struct {
	Config *Config
	FlowConfig *AuthorizationCodeFlowConfig
}

type AuthorizationCodeFlowConfig struct {
	Scopes      string
	CallbackURI string
	PKCE		bool
}

func (c *AuthorizationCodeFlow) Run() error {
	c.Config.DiscoverEndpoints()

	HandleOpenIDFlow(c.Config.ClientID, c.Config.ClientSecret, c.FlowConfig.Scopes, "http://localhost:9555/callback", c.Config.DiscoveryEndpoint, c.Config.AuthorizationEndpoint, c.Config.TokenEndpoint, c.FlowConfig.PKCE)
	return nil
}