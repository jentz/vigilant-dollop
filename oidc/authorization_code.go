package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jentz/oidc-cli/crypto"
	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"
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
	CustomArgs  *httpclient.CustomArgs
	PKCE        bool
	PAR         bool
	DPoP        bool
}

func (c *AuthorizationCodeFlow) Run(ctx context.Context) error {
	client := c.Config.Client

	if c.FlowConfig.PKCE && c.Config.ClientSecret == "" {
		c.Config.AuthMethod = httpclient.AuthMethodNone
	}

	authCodeReq := &httpclient.AuthorizationCodeRequest{
		ClientID:    c.Config.ClientID,
		Scope:       c.FlowConfig.Scopes,
		RedirectURI: c.FlowConfig.CallbackURI,
		Prompt:      c.FlowConfig.Prompt,
		AcrValues:   c.FlowConfig.AcrValues,
		LoginHint:   c.FlowConfig.LoginHint,
		MaxAge:      c.FlowConfig.MaxAge,
		UILocales:   c.FlowConfig.UILocales,
		State:       c.FlowConfig.State,
		CustomArgs:  c.FlowConfig.CustomArgs,
	}

	var codeVerifier string
	var err error
	if c.FlowConfig.PKCE {
		codeVerifier, err = crypto.GeneratePKCECodeVerifier()
		if err != nil {
			return fmt.Errorf("failed to generate PKCE code verifier: %w", err)
		}
		authCodeReq.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
		authCodeReq.CodeChallengeMethod = "S256"
	}

	if c.FlowConfig.PAR {
		parReq := &httpclient.PushedAuthorizationRequest{
			ClientID:     c.Config.ClientID,
			ClientSecret: c.Config.ClientSecret,
			AuthMethod:   c.Config.AuthMethod,
		}

		requestParams, err := httpclient.CreateAuthorizationCodeRequestValues(authCodeReq)
		parReq.Params = requestParams
		if err != nil {
			return fmt.Errorf("failed to create authorization code request values: %w", err)
		}
		resp, err := client.ExecutePushedAuthorizationRequest(ctx, c.Config.PushedAuthorizationRequestEndpoint, parReq)
		if err != nil {
			return fmt.Errorf("pushed authorization request failed: %w", err)
		}
		parResp, err := httpclient.ParsePushedAuthorizationResponse(resp)
		if err != nil {
			return c.wrapError(err, "pushed authorization")
		}

		// Use the request URI from the PAR response
		authCodeReq.RequestURI = parResp.RequestURI
	}

	aResp, err := client.ExecuteAuthorizationCodeRequest(ctx, c.Config.AuthorizationEndpoint, c.FlowConfig.CallbackURI, authCodeReq)
	if err != nil {
		return fmt.Errorf("authorization request failed: %w", err)
	}

	headers := make(map[string]string)
	if c.FlowConfig.DPoP {
		dpopProof, err := crypto.NewDPoPProof(
			c.Config.PublicKey,
			c.Config.PrivateKey,
			"POST",
			c.Config.TokenEndpoint)
		if err != nil {
			return err
		}
		headers["DPoP"] = dpopProof.String()
	}

	tokenRequest := httpclient.CreateAuthCodeTokenRequest(
		c.Config.ClientID,
		c.Config.ClientSecret,
		c.Config.AuthMethod,
		aResp.Code,
		c.FlowConfig.CallbackURI,
		codeVerifier)

	resp, err := client.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, tokenRequest, headers)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		return c.wrapError(err, "token")
	}

	// Print available response data
	if tokenData != nil {
		prettyJSON, _ := json.MarshalIndent(tokenData, "", "  ")
		log.Outputf("%s\n", string(prettyJSON))
	}
	return nil
}

func (c *AuthorizationCodeFlow) wrapError(err error, context string) error {
	switch {
	case errors.Is(err, httpclient.ErrParsingJSON):
		return fmt.Errorf("invalid JSON response in %s: %w", context, err)
	case errors.Is(err, httpclient.ErrOAuthError):
		return fmt.Errorf("authorization server rejected %s request: %w", context, err)
	case errors.Is(err, httpclient.ErrHTTPFailure):
		return fmt.Errorf("HTTP request failed in %s: %w", context, err)
	default:
		return fmt.Errorf("%s error: %w", context, err)
	}
}
