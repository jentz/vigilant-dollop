package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type IntrospectionRequest struct {
	Endpoint      string
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
	BearerToken   string
}

func (tReq *IntrospectionRequest) Execute() (tResp *IntrospectionResponse, err error) {
	vals := url.Values{}
	vals.Set("token", tReq.Token)
	vals.Set("token_type_hint", tReq.TokenTypeHint)

	fmt.Fprintf(os.Stderr, "introspection endpoint: %s\n", tReq.Endpoint)
	fmt.Fprintf(os.Stderr, "introspection request body: %s\n", vals.Encode())
	
	req, err := http.NewRequest("POST", tReq.Endpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(tReq.ClientID, tReq.ClientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("token introspection request failed: " + resp.Status)
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&tResp)
	if err != nil {
		return nil, errors.New("failed to parse introspection response")
	}

	return tResp, nil
}
