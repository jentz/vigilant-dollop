package oidc

type AuthorizationCodeFlow struct {
	ServerConfig *ServerConfig
	ClientConfig *ClientConfig
	Scopes	     *string
	CallbackURI  *string
}

func NewAuthorizationCodeFlow(serverConf *ServerConfig, clientConf *ClientConfig, scopes, callbackURI *string) *AuthorizationCodeFlow {
	return &AuthorizationCodeFlow{
		ServerConfig: serverConf,
		ClientConfig: clientConf,
		Scopes: scopes,
		CallbackURI: callbackURI,
	}
}

func (c *AuthorizationCodeFlow) Run() error {
	HandleOpenIDFlow(c.ClientConfig.ClientID, c.ClientConfig.ClientSecret, *c.Scopes, "http://localhost:9555/callback", c.ServerConfig.DiscoveryEndpoint, c.ServerConfig.AuthorizationEndpoint, c.ServerConfig.TokenEndpoint)
	return nil
}