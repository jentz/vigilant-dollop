package oidc

type AuthorizationCodeFlow struct {
	Config     *Config
	FlowConfig *AuthorizationCodeFlowConfig
}

type AuthorizationCodeFlowConfig struct {
	Scopes      string
	CallbackURI string
	CustomArgs  CustomArgs
	PKCE        bool
}

func (c *AuthorizationCodeFlow) Run() error {
	c.Config.DiscoverEndpoints()

	HandleOpenIDFlow(c.Config.ClientID, c.Config.ClientSecret, c.FlowConfig.Scopes, "http://localhost:9555/callback", c.Config.DiscoveryEndpoint, c.Config.AuthorizationEndpoint, c.Config.TokenEndpoint, c.FlowConfig.CustomArgs, c.FlowConfig.PKCE)
	return nil
}
