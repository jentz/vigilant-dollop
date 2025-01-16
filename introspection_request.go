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

	"github.com/gorilla/schema"
)

type IntrospectionRequest struct {
	Token          string          `schema:"token"`
	TokenTypeHint  string          `schema:"token_type_hint"`
	ClientID       string          `schema:"client_id"`
	ClientSecret   string          `schema:"client_secret"`
	BearerToken    string          `schema:"-"` // not part of the request
	ResponseFormat string          `schema:"-"` // not part of the request
	AuthMethod     AuthMethodValue `schema:"-"` // not part of the request
}

func (tReq *IntrospectionRequest) Execute(introspectionEndpoint string, verbose bool, httpClient *http.Client) (tResp *IntrospectionResponse, err error) {
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
		fmt.Fprintf(os.Stderr, "introspection endpoint: %s\n", introspectionEndpoint)
		maskedBody := url.Values{}
		for k, v := range body {
			if k == "client_secret" {
				maskedBody.Set(k, "*****")
			} else {
				maskedBody[k] = v
			}
		}
		if len(maskedBody) > 0 {
			fmt.Fprintf(os.Stderr, "introspection request body: %s\n", maskedBody.Encode())
		}
	}

	req, err := http.NewRequest("POST", introspectionEndpoint, strings.NewReader(body.Encode()))

	if err != nil {
		return nil, err
	}

	if tReq.AuthMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(tReq.ClientID, tReq.ClientSecret)
	}

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

	if verbose {
		fmt.Fprintf(os.Stderr, "introspection response status: %s\n", resp.Status)
	}

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
