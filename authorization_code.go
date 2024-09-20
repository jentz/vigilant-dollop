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
	Prompt      string
	AcrValues   string
	LoginHint   string
	MaxAge      string
	UILocales   string
	State       string
	PKCE        bool
	CustomArgs  CustomArgs
}

func (c *AuthorizationCodeFlow) Run() error {
	c.Config.DiscoverEndpoints()

	aReq := AuthorizationRequest{
		ResponseType: "code",
		ClientID:     c.Config.ClientID,
		Scope:        c.FlowConfig.Scopes,
		RedirectURI:  c.FlowConfig.CallbackURI,
		Prompt:       c.FlowConfig.Prompt,
		AcrValues:    c.FlowConfig.AcrValues,
		LoginHint:    c.FlowConfig.LoginHint,
		MaxAge:       c.FlowConfig.MaxAge,
		UILocales:    c.FlowConfig.UILocales,
		State:        c.FlowConfig.State,
	}

	var codeVerifier string
	if c.FlowConfig.PKCE {
		// Starting with a byte array of 31-96 bytes ensures that the base64 encoded string will be between 43 and 128 characters long as required by RFC7636
		codeVerifier = pkceCodeVerifier(randomInt(32, 96))
		aReq.CodeChallenge = pkceCodeChallenge(codeVerifier)
		aReq.CodeChallengeMethod = "S256"
	}

	aResp, err := aReq.Execute(c.Config.AuthorizationEndpoint, c.FlowConfig.CustomArgs...)
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
