package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type TokenRequest struct {
	Endpoint     string
	GrantType    string
	Code         string
	CodeVerifier string
	RedirectURI  string
	Scope        string
	ClientID     string
	ClientSecret string
}

func (tReq *TokenRequest) Execute() (tResp *TokenResponse, err error) {
	vals := url.Values{}
	vals.Set("grant_type", tReq.GrantType)

	if tReq.Scope != "" {
		vals.Set("scope", tReq.Scope)
	}

	if tReq.GrantType == "client_credentials" {
		vals.Set("client_id", tReq.ClientID)
		vals.Set("client_secret", tReq.ClientSecret)
	} else if tReq.GrantType == "authorization_code" {
		vals.Set("code", tReq.Code)
		vals.Set("redirect_uri", tReq.RedirectURI)
		if tReq.CodeVerifier != "" {
			vals.Set("code_verifier", tReq.CodeVerifier)
		}
	} else {
		return nil, fmt.Errorf("grant type not implemented yet: %s", tReq.GrantType)
	}

	fmt.Fprintf(os.Stderr, "token endpoint: %s\n", tReq.Endpoint)
	fmt.Fprintf(os.Stderr, "token request body: %s\n", vals.Encode())

	req, err := http.NewRequest("POST", tReq.Endpoint, strings.NewReader(vals.Encode()))

	// Set basic auth if username and password are provided
	if tReq.ClientID != "" && tReq.GrantType == "authorization_code" {
		req.SetBasicAuth(tReq.ClientID, tReq.ClientSecret)
	}

	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stderr, "token response status: %s\n", resp.Status)
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&tResp)
	if err != nil {
		return nil, fmt.Errorf("error while parsing token response")
	}

	return tResp, nil
}
