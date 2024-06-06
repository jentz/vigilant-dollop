package oidc

type AuthorizationCodeFlow struct {
	ServerConfig *ServerConfig
	ClientConfig *ClientConfig
	FlowConfig   *AuthorizationCodeFlowConfig
}

type AuthorizationCodeFlowConfig struct {
	Scopes      string
	CallbackURI string
}

func (c *AuthorizationCodeFlow) Run() error {
	c.ServerConfig.DiscoverEndpoints()

	HandleOpenIDFlow(c.ClientConfig.ClientID, c.ClientConfig.ClientSecret, c.FlowConfig.Scopes, "http://localhost:9555/callback", c.ServerConfig.DiscoveryEndpoint, c.ServerConfig.AuthorizationEndpoint, c.ServerConfig.TokenEndpoint)
	return nil
}