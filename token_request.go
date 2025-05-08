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

type TokenRequest struct {
	GrantType    string          `schema:"grant_type"`
	Code         string          `schema:"code,omitempty"`
	CodeVerifier string          `schema:"code_verifier,omitempty"`
	RedirectURI  string          `schema:"redirect_uri,omitempty"`
	Scope        string          `schema:"scope,omitempty"`
	ClientID     string          `schema:"client_id,omitempty"`
	ClientSecret string          `schema:"client_secret,omitempty"`
	RefreshToken string          `schema:"refresh_token,omitempty"`
	AuthMethod   AuthMethodValue `schema:"-"` // not part of the request
	DPoPHeader   string          `schema:"-"` // not part of the request
}

func (tReq *TokenRequest) Execute(tokenEndpoint string, verbose bool, httpClient *http.Client) (tResp *TokenResponse, err error) {
	encoder := schema.NewEncoder()
	body := url.Values{}
	err = encoder.Encode(tReq, body)
	if err != nil {
		return nil, err
	}

	if tReq.AuthMethod == AuthMethodClientSecretBasic {
		body.Del("client_id")
		body.Del("client_secret")
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "token endpoint: %s\n", tokenEndpoint)
		maskedBody := url.Values{}
		for k, v := range body {
			if k == "client_secret" {
				maskedBody.Set(k, "*****")
			} else {
				maskedBody[k] = v
			}
		}
		if len(maskedBody) > 0 {
			fmt.Fprintf(os.Stderr, "token request body: %s\n", maskedBody.Encode())
		}
	}

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if tReq.DPoPHeader != "" {
		req.Header.Add("DPoP", tReq.DPoPHeader)
	}

	if tReq.AuthMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(tReq.ClientID, tReq.ClientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Fprintf(os.Stderr, "token response status: %s\n", resp.Status)
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&tResp)
	if err != nil {
		return nil, fmt.Errorf("error while parsing token response")
	}

	return tResp, nil
}
