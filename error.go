package oidc

import "errors"

var (
	ErrIssuerInvalid = errors.New("issuer does not match")
)

type Error struct {
	ErrorType   string `json:"error,omitempty"`
	Description string `json:"error_description,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e Error) Error() string {
	message := "ErrorType=" + string(e.ErrorType)
	if e.Description != "" {
		message += " Description=" + e.Description
	}
	return message
}
