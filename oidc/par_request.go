package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jentz/oidc-cli/httpclient"
	"github.com/jentz/oidc-cli/log"

	"github.com/gorilla/schema"
)

type PushedAuthorizationRequest struct {
	ResponseType        string                `schema:"response_type"`
	ClientID            string                `schema:"client_id"`
	ClientSecret        string                `schema:"client_secret"`
	RedirectURI         string                `schema:"redirect_uri"`
	Scope               string                `schema:"scope"`
	Prompt              string                `schema:"prompt,omitempty"`
	AcrValues           string                `schema:"acr_values,omitempty"`
	LoginHint           string                `schema:"login_hint,omitempty"`
	MaxAge              string                `schema:"max_age,omitempty"`
	UILocales           string                `schema:"ui_locales,omitempty"`
	State               string                `schema:"state,omitempty"`
	CodeChallengeMethod string                `schema:"code_challenge_method,omitempty"`
	CodeChallenge       string                `schema:"code_challenge,omitempty"`
	AuthMethod          httpclient.AuthMethod `schema:"-"` // not part of the request
}

func (parReq *PushedAuthorizationRequest) Execute(ctx context.Context, pushedAuthEndpoint string, httpClient *http.Client, customArgs *httpclient.CustomArgs) (parResp *PushedAuthorizationResponse, err error) {
	_, err = url.Parse(parReq.RedirectURI)
	if err != nil {
		log.Printf("unable to parse redirect uri %s because %v\n", parReq.RedirectURI, err)
		return nil, err
	}

	encoder := schema.NewEncoder()
	body := url.Values{}
	err = encoder.Encode(parReq, body)
	if err != nil {
		return nil, err
	}

	// Add custom args to the request
	if customArgs != nil {
		for k, v := range *customArgs {
			body.Set(k, v)
		}
	}

	if parReq.AuthMethod == httpclient.AuthMethodBasic {
		log.Printf("using basic auth for pushed authorization request\n")
		body.Del("client_id")
		body.Del("client_secret")
	}

	log.Printf("pushed authorization endpoint: %s\n", pushedAuthEndpoint)
	maskedBody := url.Values{}
	for k, v := range body {
		if k == "client_secret" {
			maskedBody.Set(k, "*****")
		} else {
			maskedBody[k] = v
		}
	}
	if len(maskedBody) > 0 {
		log.Printf("pushed authorization request body: %s\n", maskedBody.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, "POST", pushedAuthEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if parReq.AuthMethod == httpclient.AuthMethodBasic {
		req.SetBasicAuth(parReq.ClientID, parReq.ClientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		cerr := resp.Body.Close()
		if err == nil && cerr != nil {
			err = cerr
		}
	}()

	log.Printf("pushed auth response status: %s\n", resp.Status)
	// TODO: this will all get cleaned up in the refactor
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, errors.New("error reading pushed authorization response body")
		}
		return nil, fmt.Errorf("pushed authorization request failed with status %s: %s", resp.Status, string(bodyBytes))
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&parResp)
	if err != nil {
		return nil, errors.New("error while parsing pushed authorization response")
	}

	return parResp, nil
}
