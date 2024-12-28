package oidc

import (
	"encoding/json"
)

type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (parResp *PushedAuthorizationResponse) JSON() (string, error) {
	jsonStr, err := json.Marshal(parResp)
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}
