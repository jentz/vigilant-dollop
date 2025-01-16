package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/schema"
)

type PushedAuthorizationRequest struct {
	ResponseType        string          `schema:"response_type"`
	ClientID            string          `schema:"client_id"`
	ClientSecret        string          `schema:"client_secret"`
	RedirectURI         string          `schema:"redirect_uri"`
	Scope               string          `schema:"scope"`
	Prompt              string          `schema:"prompt,omitempty"`
	AcrValues           string          `schema:"acr_values,omitempty"`
	LoginHint           string          `schema:"login_hint,omitempty"`
	MaxAge              string          `schema:"max_age,omitempty"`
	UILocales           string          `schema:"ui_locales,omitempty"`
	State               string          `schema:"state,omitempty"`
	CodeChallengeMethod string          `schema:"code_challenge_method,omitempty"`
	CodeChallenge       string          `schema:"code_challenge,omitempty"`
	AuthMethod          AuthMethodValue `schema:"-"` // not part of the request
}

func (parReq *PushedAuthorizationRequest) Execute(pushedAuthEndpoint string, verbose bool, httpClient *http.Client, customArgs ...string) (parResp *PushedAuthorizationResponse, err error) {

	_, err = url.Parse(parReq.RedirectURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to parse redirect uri %s because %v\n", parReq.RedirectURI, err)
		return nil, err
	}

	encoder := schema.NewEncoder()
	body := url.Values{}
	err = encoder.Encode(parReq, body)
	if err != nil {
		return nil, err
	}

	// Add custom args to the request
	for _, arg := range customArgs {
		kv := strings.SplitN(arg, "=", 2)
		body.Set(kv[0], kv[1])
	}

	if parReq.AuthMethod == AuthMethodClientSecretBasic {
		body.Del("client_id")
		body.Del("client_secret")
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "pushed authorization endpoint: %s\n", pushedAuthEndpoint)
		maskedBody := url.Values{}
		for k, v := range body {
			if k == "client_secret" {
				maskedBody.Set(k, "*****")
			} else {
				maskedBody[k] = v
			}
		}
		if len(maskedBody) > 0 {
			fmt.Fprintf(os.Stderr, "pushed authorization request body: %s\n", maskedBody.Encode())
		}
	}

	req, err := http.NewRequest("POST", pushedAuthEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if parReq.AuthMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(parReq.ClientID, parReq.ClientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Fprintf(os.Stderr, "pushed auth response status: %s\n", resp.Status)
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&parResp)
	if err != nil {
		return nil, fmt.Errorf("error while parsing pushed authorization response")
	}

	return parResp, nil
}
