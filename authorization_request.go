package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"github.com/jentz/vigilant-dollop/pkg/log"
	"github.com/jentz/vigilant-dollop/pkg/webflow"
)

type AuthorizationRequest struct {
	ResponseType        string `schema:"response_type,omitempty"`
	ClientID            string `schema:"client_id"`
	RedirectURI         string `schema:"redirect_uri,omitempty"`
	Scope               string `schema:"scope,omitempty"`
	Prompt              string `schema:"prompt,omitempty"`
	AcrValues           string `schema:"acr_values,omitempty"`
	LoginHint           string `schema:"login_hint,omitempty"`
	MaxAge              string `schema:"max_age,omitempty"`
	UILocales           string `schema:"ui_locales,omitempty"`
	State               string `schema:"state,omitempty"`
	CodeChallengeMethod string `schema:"code_challenge_method,omitempty"`
	CodeChallenge       string `schema:"code_challenge,omitempty"`
	RequestURI          string `schema:"request_uri,omitempty"`
}

func (aReq *AuthorizationRequest) Execute(authEndpoint string, callback string, customArgs ...string) (aResp *AuthorizationResponse, err error) {

	callbackServer, err := webflow.NewCallbackServer(callback)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback server: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	go func() {
		if err := callbackServer.Start(ctx); err != nil && err != http.ErrServerClosed {
			log.Errorf("callback server failed to start: %v\n", err)
		}
	}()

	authURL, err := url.Parse(authEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth endpoint: %w", err)
	}

	encoder := schema.NewEncoder()
	query := authURL.Query()
	err = encoder.Encode(aReq, query)
	if err != nil {
		return nil, fmt.Errorf("failed to encode parameters: %w", err)
	}

	// Add custom args to the query string
	for _, arg := range customArgs {
		kv := strings.SplitN(arg, "=", 2)
		query.Set(kv[0], kv[1])
	}

	authURL.RawQuery = query.Encode()
	requestURL := authURL.String()

	log.Printf("authorization request: %s\n", requestURL)

	browser := webflow.NewSystemBrowser()
	err = browser.Open(requestURL)
	if err != nil {
		log.Errorf("unable to open webflow because %v, visit %s to continue\n", err, requestURL)
	}

	callbackResp, err := callbackServer.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("callback failed: %w", err)
	}

	if callbackResp.Code == "" {
		return nil, fmt.Errorf("authorization failed with error %s and description %s", callbackResp.ErrorMsg, callbackResp.ErrorDescription)
	}

	return &AuthorizationResponse{
		Code: callbackResp.Code,
	}, nil
}
