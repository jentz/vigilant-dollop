package oidc

import (
	"crypto/tls"
	"fmt"
	"net/http"
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
	PAR         bool
}

func (c *AuthorizationCodeFlow) Run() error {
	c.Config.DiscoverEndpoints()

	aReq := AuthorizationRequest{}
	var codeVerifier string

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Config.SkipTLSVerify,
			},
		},
	}

	if c.FlowConfig.PAR {
		parReq := PushedAuthorizationRequest{
			ResponseType: "code",
			ClientID:     c.Config.ClientID,
			ClientSecret: c.Config.ClientSecret,
			Scope:        c.FlowConfig.Scopes,
			RedirectURI:  c.FlowConfig.CallbackURI,
			Prompt:       c.FlowConfig.Prompt,
			AcrValues:    c.FlowConfig.AcrValues,
			LoginHint:    c.FlowConfig.LoginHint,
			MaxAge:       c.FlowConfig.MaxAge,
			UILocales:    c.FlowConfig.UILocales,
			State:        c.FlowConfig.State,
			AuthMethod:   c.Config.AuthMethod,
		}
		if c.FlowConfig.PKCE {
			// Starting with a byte array of 31-96 bytes ensures that the base64 encoded string will be between 43 and 128 characters long as required by RFC7636
			codeVerifier = pkceCodeVerifier(randomInt(32, 96))
			parReq.CodeChallenge = pkceCodeChallenge(codeVerifier)
			parReq.CodeChallengeMethod = "S256"
		}
		parResp, err := parReq.Execute(c.Config.PushedAuthorizationRequestEndpoint, c.Config.Verbose, client, c.FlowConfig.CustomArgs...)
		if err != nil {
			return err
		}
		aReq = AuthorizationRequest{
			ClientID:   c.Config.ClientID,
			RequestURI: parResp.RequestURI,
		}
	} else {
		// regular authorization code flow
		aReq = AuthorizationRequest{
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
		if c.FlowConfig.PKCE {
			// Starting with a byte array of 31-96 bytes ensures that the base64 encoded string will be between 43 and 128 characters long as required by RFC7636
			codeVerifier = pkceCodeVerifier(randomInt(32, 96))
			aReq.CodeChallenge = pkceCodeChallenge(codeVerifier)
			aReq.CodeChallengeMethod = "S256"
		}
	}

	aResp, err := aReq.Execute(c.Config.AuthorizationEndpoint, c.FlowConfig.CallbackURI, c.Config.Verbose, c.FlowConfig.CustomArgs...)
	if err != nil {
		return err
	}

	tReq := TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		AuthMethod:   c.Config.AuthMethod,
		RedirectURI:  c.FlowConfig.CallbackURI,
		CodeVerifier: codeVerifier,
		Code:         aResp.Code,
	}

	tResp, err := tReq.Execute(c.Config.TokenEndpoint, c.Config.Verbose, client)

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
