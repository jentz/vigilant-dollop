package oidc

import (
	"encoding/json"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

func (tResp *TokenResponse) JSON() (string, error) {
	jsonStr, err := json.Marshal(tResp)
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}
