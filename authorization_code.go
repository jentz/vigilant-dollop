package oidc

import (
	"context"
	"fmt"
	"github.com/jentz/oidc-cli/pkg/crypto"
	"github.com/jentz/oidc-cli/pkg/log"
)

type AuthorizationCodeFlow struct {
	Config     *Config
	FlowConfig *AuthorizationCodeFlowConfig
	client     *Client
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
	DPoP        bool
}

func (c *AuthorizationCodeFlow) Run(ctx context.Context) error {
	c.client = NewClient(c.Config)

	err := c.Config.DiscoverEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("failed to discover endpoints: %w", err)
	}

	err = c.Config.ReadKeyFiles()
	if err != nil {
		return fmt.Errorf("failed to read key files: %w", err)
	}

	aReq := AuthorizationRequest{}
	var codeVerifier string

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
			codeVerifier = crypto.GeneratePKCECodeVerifier(crypto.RandomInt(32, 96))
			parReq.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
			parReq.CodeChallengeMethod = "S256"
		}
		parResp, err := parReq.Execute(ctx, c.Config.PushedAuthorizationRequestEndpoint, c.client.http, c.FlowConfig.CustomArgs...)
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
			codeVerifier = crypto.GeneratePKCECodeVerifier(crypto.RandomInt(32, 96))
			aReq.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
			aReq.CodeChallengeMethod = "S256"
		}
	}

	aResp, err := aReq.Execute(ctx, c.Config.AuthorizationEndpoint, c.FlowConfig.CallbackURI, c.FlowConfig.CustomArgs...)
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

	if c.FlowConfig.DPoP {
		dpopProof, err := crypto.NewDPoPProof(
			c.Config.PublicKey,
			c.Config.PrivateKey,
			"POST",
			c.Config.TokenEndpoint)
		if err != nil {
			return err
		}
		tReq.DPoPHeader = dpopProof.String()
	}

	tResp, err := tReq.Execute(ctx, c.Config.TokenEndpoint, c.client.http)
	if err != nil {
		return err
	}

	jsonStr, err := tResp.JSON()
	if err != nil {
		return err
	}

	log.Outputf(jsonStr + "\n")
	return nil
}
