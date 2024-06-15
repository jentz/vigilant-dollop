package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type TokenRequest struct {
	Endpoint 	 string
	GrantType    string
	Code         string
	RedirectURI  string
	Scope		 string
	ClientID     string
	ClientSecret string
	Username	 string
	Password	 string
}

func (tReq *TokenRequest) Execute() (tResp *TokenResponse, err error) {
	vals := url.Values{}
	vals.Set("grant_type", tReq.GrantType)
	vals.Set("client_id", tReq.ClientID)
	if (tReq.GrantType == "client_credentials") {
		vals.Set("client_secret", tReq.ClientSecret)
	} else{
		return nil, errors.New("grant type not implemented yet")
	}

	req, err := http.NewRequest("POST", tReq.Endpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&tResp)
	if err != nil {
		return nil, errors.New("error while parsing token response")
	}

	return tResp, nil
}