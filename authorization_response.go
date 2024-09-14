package oidc

import "encoding/json"

type AuthorizationResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	Code         string `json:"code"`
}

func (aResp *AuthorizationResponse) JSON() (string, error) {
	jsonStr, err := json.Marshal(aResp)
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}
