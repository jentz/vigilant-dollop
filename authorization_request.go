package oidc

import (
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
	"net/url"
	"strings"

	"github.com/gorilla/schema"
	"github.com/jentz/vigilant-dollop/pkg/browser"
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

func (aReq *AuthorizationRequest) Execute(authEndpoint string, callback string, verbose bool, customArgs ...string) (aResp *AuthorizationResponse, err error) {
	callbackEndpoint := &callbackEndpoint{}
	callbackURL, err := url.Parse(callback)
	if err != nil {
		log.ErrPrintf("unable to parse redirect uri %s because %v\n", aReq.RedirectURI, err)
		return nil, err
	}
	callbackEndpoint.start(callbackURL.Host, callbackURL.Path, verbose)

	authURL, err := url.Parse(authEndpoint)
	if err != nil {
		return nil, err
	}

	encoder := schema.NewEncoder()
	query := authURL.Query()
	err = encoder.Encode(aReq, query)
	if err != nil {
		return nil, err
	}

	// Add custom args to the query string
	for _, arg := range customArgs {
		kv := strings.SplitN(arg, "=", 2)
		query.Set(kv[0], kv[1])
	}

	authURL.RawQuery = query.Encode()
	requestURL := authURL.String()

	if verbose {
		log.ErrPrintf("authorization request: %s\n", requestURL)
	}

	err = browser.OpenURL(requestURL)
	if err != nil {
		log.ErrPrintf("unable to open browser because %v, visit %s to continue\n", err, requestURL)
	}

	<-callbackEndpoint.shutdownSignal
	callbackEndpoint.stop()

	if callbackEndpoint.code != "" {
		aResp = &AuthorizationResponse{}
		aResp.Code = callbackEndpoint.code
		return aResp, nil
	}
	return nil, fmt.Errorf("authorization failed with error %s and description %s", callbackEndpoint.errorMsg, callbackEndpoint.errorDescription)
}
