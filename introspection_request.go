package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/schema"
)

type IntrospectionRequestPayload struct {
	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint"`
	ClientID      string `schema:"client_id,omitempty"`
	ClientSecret  string `schema:"client_secret,omitempty"`
}

type IntrospectionRequestBuilder struct {
	endpoint       string
	header  *http.Header
	payload *IntrospectionRequestPayload
	clientID       string
	clientSecret   string
	bearerToken    string
	authMethod     AuthMethodValue
	errs           []error
}

func NewIntrospectionRequestBuilder() *IntrospectionRequestBuilder {
	b := new(IntrospectionRequestBuilder)
	b.payload = new(IntrospectionRequestPayload)
	b.payload.TokenTypeHint = "access_token"
	b.header = new(http.Header)
	b.header.Set("Content-Type", "application/x-www-form-urlencoded")
	b.header.Set("Accept", "application/json")
	b.authMethod = AuthMethodClientSecretBasic
	return b
}

func (b *IntrospectionRequestBuilder) SetToken(token string) *IntrospectionRequestBuilder {
	b.payload.Token = token
	return b
}

func (b *IntrospectionRequestBuilder) SetTokenTypeHint(tokenTypeHint string) *IntrospectionRequestBuilder {
	// token_type_hint can be access_token or refresh_token, see:
	// https://datatracker.ietf.org/doc/html/rfc7662#section-2
	// https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2
	if !contains(SupportedIntrospectionTokenTypeHints(), tokenTypeHint) {
		b.errs = append(b.errs, fmt.Errorf("invalid token type hint %s, valid values are %s", tokenTypeHint, SupportedIntrospectionTokenTypeHints()))
		return b
	}
	b.payload.TokenTypeHint = tokenTypeHint
	return b
}

func (b *IntrospectionRequestBuilder) SetClientID(clientID string) *IntrospectionRequestBuilder {
	b.clientID = clientID
	return b
}

func (b *IntrospectionRequestBuilder) SetClientSecret(clientSecret string) *IntrospectionRequestBuilder {
	b.clientSecret = clientSecret
	return b
}

func (b *IntrospectionRequestBuilder) SetBearerToken(bearerToken string) *IntrospectionRequestBuilder {
	b.bearerToken = bearerToken
	return b
}

func (b *IntrospectionRequestBuilder) SetResponseFormat(responseFormat string) *IntrospectionRequestBuilder {
	// supports setting a different accept header than application/json
	// see: https://www.rfc-editor.org/rfc/rfc9701.html#name-requesting-a-jwt-response
	if !contains(SupportedIntrospectionResponseFormats(), responseFormat) {
		b.errs = append(b.errs, fmt.Errorf("invalid response format %s, valid values are %s", responseFormat, SupportedIntrospectionResponseFormats()))
		return b
	}
	b.header.Set("Accept", "application/"+responseFormat)
	return b
}

func (b *IntrospectionRequestBuilder) SetAuthMethod(authMethod AuthMethodValue) *IntrospectionRequestBuilder {
	if !contains(SupportedIntrospectionAuthMethods(), authMethod) {
		b.errs = append(b.errs, fmt.Errorf("invalid auth method %s, valid values are %s", authMethod, SupportedIntrospectionAuthMethods()))
		return b
	}
	b.authMethod = authMethod
	return b
}

func (b *IntrospectionRequestBuilder) SetEndpoint(endpoint string) *IntrospectionRequestBuilder {
	b.endpoint = endpoint
	return b
}

func (b *IntrospectionRequestBuilder) Build() (req *http.Request, err error) {
	ctx := context.Background()

	// validate the request
	if b.payload.Token == "" {
		return nil, errors.New("token is required")
	}

	if (b.authMethod == AuthMethodClientSecretBasic || b.authMethod == AuthMethodClientSecretPost) && 
		(b.clientID == "" || b.clientSecret == "") {
		return nil, errors.New("client_id and client_secret are required for client_secret_basic and client_secret_post auth methods")
	}

	if (b.bearerToken == "" && (b.clientID == "" || b.clientSecret == "")) {
		return nil, errors.New("client_id and client_secret are required unless a bearer token is provided")	
	}

	if (b.bearerToken != "" && (b.clientID != "" || b.clientSecret != "")) {
		return nil, errors.New("client_id and client_secret are mutually exclusive with bearer token")
	}

	req, err = http.NewRequestWithContext(ctx, "POST", b.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	// set authorization method
	if b.bearerToken != "" {
		b.header.Set("Authorization", "Bearer "+b.bearerToken)
	} else if b.authMethod == AuthMethodClientSecretBasic {
		req.SetBasicAuth(b.payload.ClientID, b.payload.ClientSecret)
	} else if b.authMethod == AuthMethodClientSecretPost {
		b.payload.ClientID = b.clientID
		b.payload.ClientSecret = b.clientSecret
	}

	encoder := schema.NewEncoder()
	body := url.Values{}
	err = encoder.Encode(b.payload, body)
	if err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(strings.NewReader(body.Encode()))
	req.Header = *b.header

	return req, err
}


// 	dec := json.NewDecoder(resp.Body)
// 	err = dec.Decode(&tResp)
// 	if err != nil {
// 		if tReq.ResponseFormat == "json" {
// 			return nil, errors.New("failed to parse introspection response")
// 		} else {
// 			// assume the response is a plain JWT
// 			body, err := io.ReadAll(resp.Body)
// 			if err != nil {
// 				return nil, errors.New("failed to read introspection response body")
// 			}
// 			tResp = &IntrospectionResponse{
// 				Active: true,
// 				Jwt:    string(body),
// 			}
// 		}
// 	}

// 	return tResp, nil
// }
