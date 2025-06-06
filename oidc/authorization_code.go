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
	CustomArgs  *httpclient.CustomArgs
	PKCE        bool
	PAR         bool
	DPoP        bool
}

func (c *AuthorizationCodeFlow) Run(ctx context.Context) error {
	c.client = NewClient(c.Config)

	if c.FlowConfig.PKCE && c.Config.ClientSecret == "" {
		c.Config.AuthMethod = httpclient.AuthMethodNone
	}

	var aReq *httpclient.AuthorizationCodeRequest
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
			codeVerifier, err := crypto.GeneratePKCECodeVerifier()
			if err != nil {
				return fmt.Errorf("failed to generate PKCE code verifier: %w", err)
			}
			parReq.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
			parReq.CodeChallengeMethod = "S256"
		}
		parResp, err := parReq.Execute(ctx, c.Config.PushedAuthorizationRequestEndpoint, c.client.http, c.FlowConfig.CustomArgs)
		if err != nil {
			return err
		}
		aReq = &httpclient.AuthorizationCodeRequest{
			ClientID:   c.Config.ClientID,
			RequestURI: parResp.RequestURI,
		}
	} else {
		// regular authorization code flow
		aReq = &httpclient.AuthorizationCodeRequest{
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
		if c.FlowConfig.PKCE {
			codeVerifier, err := crypto.GeneratePKCECodeVerifier()
			if err != nil {
				return fmt.Errorf("failed to generate PKCE code verifier: %w", err)
			}
			aReq.CodeChallenge = crypto.GeneratePKCECodeChallenge(codeVerifier)
			aReq.CodeChallengeMethod = "S256"
		}
	}

	httpClient := c.Config.Client
	aResp, err := httpClient.ExecuteAuthorizationCodeRequest(ctx, c.Config.AuthorizationEndpoint, c.FlowConfig.CallbackURI, aReq)
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

	resp, err := httpClient.ExecuteTokenRequest(ctx, c.Config.TokenEndpoint, tokenRequest, headers)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}

	tokenData, err := httpclient.ParseTokenResponse(resp)
	if err != nil {
		if errors.Is(err, httpclient.ErrParsingJSON) {
			return fmt.Errorf("invalid JSON response: %w", err)
		} else if errors.Is(err, httpclient.ErrOAuthError) {
			return fmt.Errorf("authorization server rejected request: %w", err)
		} else if errors.Is(err, httpclient.ErrHTTPFailure) {
			return fmt.Errorf("HTTP request failed: %w", err)
		}
		return fmt.Errorf("token error: %w", err)
	}

	// Print available response data
	if tokenData != nil {
		prettyJSON, _ := json.MarshalIndent(tokenData, "", "  ")
		log.Outputf("%s\n", string(prettyJSON))
	}
	return nil
}
