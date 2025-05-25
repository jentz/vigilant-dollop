package oidc

import (
	"context"
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

type IntrospectionRequest struct {

	// payload contains the data required to construct the request
	payload *IntrospectionRequestPayload

	// clientID, clientSecret, and bearerToken are used for authentication
	clientID     string
	clientSecret string

	// authMethod specifies the authentication method to use for the request
	authMethod AuthMethodValue

	// errs is a slice of errors encountered while building the request
	errs []error

	// inherit fields from http.Request
	http.Request
}

func NewIntrospectionRequest(token string, endpoint string) *IntrospectionRequest {
	b := new(IntrospectionRequest)
	b.URL, _ = url.Parse(endpoint)
	b.Method = http.MethodPost
	b.payload = new(IntrospectionRequestPayload)
	b.payload.Token = token
	b.Header = http.Header{}
	b.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b.Header.Set("Accept", "application/json")
	b.authMethod = AuthMethodClientSecretBasic
	return b
}

func (b *IntrospectionRequest) WithTokenTypeHint(tokenTypeHint string) *IntrospectionRequest {
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

func (b *IntrospectionRequest) WithResponseFormat(responseFormat string) *IntrospectionRequest {
	// supports setting a different accept header than application/json
	// see: https://www.rfc-editor.org/rfc/rfc9701.html#name-requesting-a-jwt-response
	if !contains(SupportedIntrospectionResponseFormats(), responseFormat) {
		b.errs = append(b.errs, fmt.Errorf("invalid response format %s, valid values are %s", responseFormat, SupportedIntrospectionResponseFormats()))
		return b
	}
	b.Header.Set("Accept", "application/"+responseFormat)
	return b
}

func (b *IntrospectionRequest) WithBearerToken(bearerToken string) *IntrospectionRequest {
	// bearerToken is used for authentication, takes precedence over client credentials
	b.Header.Set("Authorization", "Bearer "+bearerToken)
	return b
}

func (b *IntrospectionRequest) WithCredentials(clientID string, clientSecret string) *IntrospectionRequest {
	b.clientID = clientID
	b.clientSecret = clientSecret
	// use http basic authentication as the default authentication method
	b.SetBasicAuth(b.payload.ClientID, b.payload.ClientSecret)
	return b
}

func (b *IntrospectionRequest) WithAuthMethod(authMethod AuthMethodValue) *IntrospectionRequest {
	// authMethod specifies the authentication method to use for the request
	// WithAuthMethod() shall be called after WithCredentials()
	if !contains(SupportedIntrospectionAuthMethods(), authMethod) {
		b.errs = append(b.errs, fmt.Errorf("invalid auth method %s, valid values are %s", authMethod, SupportedIntrospectionAuthMethods()))
		return b
	}
	if b.authMethod == AuthMethodClientSecretPost {
		// remove a previously existing Authorization header
		b.Header.Del("Authorization")
		b.payload.ClientID = b.clientID
		b.payload.ClientSecret = b.clientSecret
	}
	return b
}

func (b *IntrospectionRequest) ToHTTPRequest() (req *http.Request, err error) {
	ctx := context.Background()

	if len(b.errs) > 0 {
		err = fmt.Errorf("introspection request has errors: %v", b.errs)
		return nil, err
	}

	encoder := schema.NewEncoder()
	body := url.Values{}
	err = encoder.Encode(b.payload, body)
	if err != nil {
		return nil, err
	}
	b.Body = io.NopCloser(strings.NewReader(body.Encode()))

	req = b.WithContext(ctx)
	return req, err
}

func (b *IntrospectionRequest) MaskedPayload() (url.Values, error) {
	encoder := schema.NewEncoder()
	body := url.Values{}
	err := encoder.Encode(b.payload, body)
	if err != nil {
		return nil, err
	}

	for k, v := range body {
		if k == "client_secret" {
			body.Set(k, "*****")
		} else {
			body[k] = v
		}
	}

	return body, nil
}
