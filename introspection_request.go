package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type IntrospectionRequest struct {
	Token          string
	TokenTypeHint  string
	ClientID       string
	ClientSecret   string
	BearerToken    string
	ResponseFormat string
}

func (tReq *IntrospectionRequest) Execute(introspectionEndpoint string, verbose bool, httpClient *http.Client) (tResp *IntrospectionResponse, err error) {
	vals := url.Values{}
	vals.Set("token", tReq.Token)
	vals.Set("token_type_hint", tReq.TokenTypeHint)

	if verbose {
		fmt.Fprintf(os.Stderr, "introspection endpoint: %s\n", introspectionEndpoint)
		fmt.Fprintf(os.Stderr, "introspection request body: %s\n", vals.Encode())
	}

	req, err := http.NewRequest("POST", introspectionEndpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(tReq.ClientID, tReq.ClientSecret)
	req.Header.Add("Accept", "application/"+tReq.ResponseFormat)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("token introspection request failed: " + resp.Status)
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stderr, "introspection response status: %s\n", resp.Status)

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&tResp)
	if err != nil {
		if tReq.ResponseFormat == "json" {
			return nil, errors.New("failed to parse introspection response")
		} else {
			// assume the response is a plain JWT
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, errors.New("failed to read introspection response body")
			}
			tResp = &IntrospectionResponse{
				Active: true,
				Jwt:    string(body),
			}
		}
	}

	return tResp, nil
}
