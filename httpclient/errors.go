package httpclient

import (
	"errors"
	"fmt"
)

// OAuth2 error types
var (
	ErrHTTPFailure = errors.New("oauth http failure")
	ErrParsingJSON = errors.New("json parsing error")
	ErrOAuthError  = errors.New("oauth protocol error")
)

// OAuth2Error represents a standard OAuth2 error response
type OAuth2Error struct {
	StatusCode       int
	ErrorType        string
	ErrorDescription string
	RawBody          string
}

func (e *OAuth2Error) Error() string {
	if e.ErrorType != "" {
		if e.ErrorDescription != "" {
			return fmt.Sprintf("oauth error: %s - %s, status: %d", e.ErrorType, e.ErrorDescription, e.StatusCode)
		}
		return fmt.Sprintf("oauth error: %s, status: %d", e.ErrorType, e.StatusCode)
	}
	return fmt.Sprintf("token request failed with status: %d, body: %s", e.StatusCode, e.RawBody)
}
