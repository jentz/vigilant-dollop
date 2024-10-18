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
	Endpoint     string
	GrantType    string `schema:"grant_type"`
	Code         string `schema:"code,omitempty"`
	CodeVerifier string `schema:"code_verifier,omitempty"`
	RedirectURI  string `schema:"redirect_uri,omitempty"`
	Scope        string `schema:"scope,omitempty"`
	ClientID     string `schema:"client_id,omitempty"`
	ClientSecret string `schema:"client_secret,omitempty"`
	RefreshToken string `schema:"refresh_token,omitempty"`
}

func (tReq *TokenRequest) Execute() (tResp *TokenResponse, err error) {
	encoder := schema.NewEncoder()
	body := url.Values{}
	err = encoder.Encode(tReq, body)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "token endpoint: %s\n", tReq.Endpoint)
	fmt.Fprintf(os.Stderr, "token request body: %s\n", body.Encode())

	req, err := http.NewRequest("POST", tReq.Endpoint, strings.NewReader(body.Encode()))
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
