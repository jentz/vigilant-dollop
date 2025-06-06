package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/webflow"
)

type AuthorizationCodeRequest struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Prompt              string
	AcrValues           string
	LoginHint           string
	MaxAge              string
	UILocales           string
	CodeChallengeMethod string
	CodeChallenge       string
	RequestURI          string
	CustomArgs          *CustomArgs
}

type AuthorizationCodeResponse struct {
	Code  string
	State string
}

// CreateAuthorizationCodeRequestURI builds the authorization request URI.
func CreateAuthorizationCodeRequestURI(endpoint string, req *AuthorizationCodeRequest) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")

	// Add required parameters
	if req.ClientID != "" {
		if req.ClientID == "" {
			return "", errors.New("client_id is required")
		}
	}
	q.Set("client_id", req.ClientID)

	// Add standard params if set
	if req.State != "" {
		q.Set("state", req.State)
	}
	if req.RedirectURI != "" {
		q.Set("redirect_uri", req.RedirectURI)
	}
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.Prompt != "" {
		q.Set("prompt", req.Prompt)
	}
	if req.AcrValues != "" {
		q.Set("acr_values", req.AcrValues)
	}
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	if req.MaxAge != "" {
		q.Set("max_age", req.MaxAge)
	}
	if req.UILocales != "" {
		q.Set("ui_locales", req.UILocales)
	}
	if req.CodeChallengeMethod != "" {
		q.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
	}
	if req.RequestURI != "" {
		q.Set("request_uri", req.RequestURI)
	}

	// Add custom args
	if req.CustomArgs != nil {
		for k, v := range *req.CustomArgs {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExecuteAuthorizationCodeRequest executes the authorization code request and returns the auth code response.
func (c *Client) ExecuteAuthorizationCodeRequest(ctx context.Context, endpoint string, callback string, req *AuthorizationCodeRequest) (*AuthorizationCodeResponse, error) {
	callbackServer, err := webflow.NewCallbackServer(callback)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback server: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	serverErrChan := make(chan error, 1)
	go func() {
		if err := callbackServer.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	// Give the server a moment to start or fail
	select {
	case err := <-serverErrChan:
		return nil, fmt.Errorf("callback server failed to start: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	authURI, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth endpoint: %w", err)
	}
	requestURI, err := CreateAuthorizationCodeRequestURI(authURI.String(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization request URI: %w", err)
	}
	log.Printf("authorization request: %s\n", requestURI)

	browser := webflow.NewBrowser()
	err = browser.Open(requestURI)
	if err != nil {
		log.Errorf("unable to open browser because %v, visit %s to continue\n", err, requestURI)
	}

	callbackResp, err := callbackServer.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("callback failed: %w", err)
	}

	if callbackResp.Code == "" {
		return nil, fmt.Errorf("authorization failed with error %s and description %s", callbackResp.ErrorMsg, callbackResp.ErrorDescription)
	}

	return &AuthorizationCodeResponse{
		Code:  callbackResp.Code,
		State: req.State, // TODO: Return the state from the callback response
	}, nil
}
