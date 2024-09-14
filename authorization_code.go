package oidc

import (
	"fmt"
)

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

	aReq := AuthorizationRequest{
		ResponseType: "code",
		Endpoint:     c.Config.AuthorizationEndpoint,
		ClientID:     c.Config.ClientID,
		Scope:        c.FlowConfig.Scopes,
		RedirectURI:  c.FlowConfig.CallbackURI,
		CustomArgs:   c.FlowConfig.CustomArgs,
	}

	var codeVerifier string
	if c.FlowConfig.PKCE {
		// Starting with a byte array of 31-96 bytes ensures that the base64 encoded string will be between 43 and 128 characters long as required by RFC7636
		codeVerifier = pkceCodeVerifier(randomInt(32, 96))
		aReq.CodeChallenge = pkceCodeChallenge(codeVerifier)
		aReq.CodeChallengeMethod = "S256"
	}

	aResp, err := aReq.Execute()
	if err != nil {
		return err
	}

	tReq := TokenRequest{
		GrantType:    "authorization_code",
		Endpoint:     c.Config.TokenEndpoint,
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		RedirectURI:  c.FlowConfig.CallbackURI,
		CodeVerifier: codeVerifier,
		Code:         aResp.Code,
	}

	tResp, err := tReq.Execute()
	if err != nil {
		return err
	}

	jsonStr, err := tResp.JSON()
	if err != nil {
		return err
	}

	fmt.Println(jsonStr)
	return nil
}
