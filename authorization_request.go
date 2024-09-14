package oidc

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jentz/vigilant-dollop/pkg/browser"
)

type AuthorizationRequest struct {
	Endpoint            string
	CustomArgs          []string
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallengeMethod string
	CodeChallenge       string
	RequestURL          string
}

func (aReq *AuthorizationRequest) URL() string {
	return aReq.RequestURL
}

func (aReq *AuthorizationRequest) Execute() (aResp *AuthorizationResponse, err error) {
	callbackEndpoint := &callbackEndpoint{}
	callbackEndpoint.start()

	authURL, err := url.Parse(aReq.Endpoint)
	if err != nil {
		return nil, err
	}
	query := authURL.Query()
	query.Set("client_id", aReq.ClientID)
	query.Set("response_type", aReq.ResponseType)
	query.Set("scope", aReq.Scope)
	query.Set("redirect_uri", aReq.RedirectURI)

	if aReq.CodeChallenge != "" && aReq.CodeChallengeMethod != "" {
		query.Set("code_challenge", aReq.CodeChallenge)
		query.Set("code_challenge_method", aReq.CodeChallengeMethod)
	}

	for _, arg := range aReq.CustomArgs {
		kv := strings.SplitN(arg, "=", 2)
		query.Set(kv[0], kv[1])
	}

	authURL.RawQuery = query.Encode()
	aReq.RequestURL = authURL.String()
	fmt.Fprintf(os.Stderr, "authorization request: %s\n", aReq.RequestURL)

	err = browser.OpenURL(aReq.RequestURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to open browser because %v, visit %s to continue\n", err, aReq.RequestURL)
	}

	<-callbackEndpoint.shutdownSignal
	callbackEndpoint.stop()

	if callbackEndpoint.code != "" {
		aResp = &AuthorizationResponse{}
		aResp.Code = callbackEndpoint.code
		return aResp, nil
	} else {
		return nil, fmt.Errorf("authorization failed with error %s and description %s", callbackEndpoint.errorMsg, callbackEndpoint.errorDescription)
	}
}
