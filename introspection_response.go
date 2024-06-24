package oidc

import (
	"encoding/json"
)

type IntrospectionResponse struct {
	Active				bool   `json:"active"`
	Scope				string `json:"scope,omitempty"`
	ClientID			string `json:"client_id,omitempty"`
	Username			string `json:"username,omitempty"`
	TokenType			string `json:"token_type,omitempty"`
	Exp					int    `json:"exp,omitempty"`
	Iat					int    `json:"iat,omitempty"`
	Nbf					int    `json:"nbf,omitempty"`
	Sub					string `json:"sub,omitempty"`
	Azp					string `json:"azp,omitempty"`
	Aud					string `json:"aud,omitempty"`
	Jti					string `json:"jti,omitempty"`
	Email				string `json:"email,omitempty"`
	EmailVerified		bool   `json:"email_verified,omitempty"`
	Phone				string `json:"phone,omitempty"`
	PhoneVerified		bool   `json:"phone_verified,omitempty"`
	Address				string `json:"address,omitempty"`
	UpdatedAt			int    `json:"updated_at,omitempty"`
	AuthTime			int    `json:"auth_time,omitempty"`
	Nonce				string `json:"nonce,omitempty"`
	Amr					string `json:"amr,omitempty"`
	ACR					string `json:"acr,omitempty"`
	AzpClientID			string `json:"azp_client_id,omitempty"`
	RealmAccess			string `json:"realm_access,omitempty"`
	ResourceAccess		string `json:"resource_access,omitempty"`
}

func (tResp *IntrospectionResponse) JSON() (string, error) {
	jsonStr, err := json.Marshal(&tResp)
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}