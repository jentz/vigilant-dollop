package httpclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
)

type PushedAuthorizationRequest struct {
	ClientID     string
	ClientSecret string
	AuthMethod   AuthMethod
	Params       *url.Values
}

type PushedAuthorizationResponse struct {
	RequestURI string
	ExpiresIn  int
}

func (c *Client) ExecutePushedAuthorizationRequest(ctx context.Context, endpoint string, req *PushedAuthorizationRequest) (*Response, error) {
	headers := make(map[string]string)

	// Apply authentication method
	switch req.AuthMethod {
	case AuthMethodBasic:
		// Use HTTP Basic Auth
		auth := base64.StdEncoding.EncodeToString([]byte(req.ClientID + ":" + req.ClientSecret))
		headers["Authorization"] = "Basic " + auth
	case AuthMethodPost:
		// Include credentials in request body
		req.Params.Set("client_id", req.ClientID)
		if req.ClientSecret != "" {
			req.Params.Set("client_secret", req.ClientSecret)
		}
	case AuthMethodNone:
		// Just include client_id in request body
		req.Params.Set("client_id", req.ClientID)
	}

	// Execute the request
	return c.PostForm(ctx, endpoint, *req.Params, headers)
}

func ParsePushedAuthorizationResponse(resp *Response) (*PushedAuthorizationResponse, error) {
	var mapResp map[string]interface{}

	if err := json.Unmarshal(resp.Body, &mapResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParsingJSON, err)
	}

	if !resp.IsSuccess() {
		oauth2Err := &OAuth2Error{
			StatusCode: resp.StatusCode,
			RawBody:    resp.String(),
		}
		// Extract standard OAuth2 error fields if present
		if errStr, ok := mapResp["error"].(string); ok {
			oauth2Err.ErrorType = errStr
			if desc, ok := mapResp["error_description"].(string); ok {
				oauth2Err.ErrorDescription = desc
			}
			return nil, fmt.Errorf("%w: %v", ErrOAuthError, oauth2Err)
		}

		return nil, fmt.Errorf("%w: %v", ErrHTTPFailure, oauth2Err)
	}

	return &PushedAuthorizationResponse{
		RequestURI: mapResp["request_uri"].(string),
		ExpiresIn:  int(mapResp["expires_in"].(float64)), // JSON numbers are float64
	}, nil
}
