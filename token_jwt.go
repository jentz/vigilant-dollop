package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)


type JWT struct {
	Header  	map[string]interface{}
	Claims		map[string]interface{}
	Signature 	string
	SHA256		[32]byte
}

func ParseJwt(tokenStr string) (*JWT, error) {
	// follow guidelines from https://datatracker.ietf.org/doc/html/rfc7519#section-7.2

	strArray := strings.Split(tokenStr, ".")
	if len(strArray) != 3 {
		return nil, errors.New("invalid jwt: provided token does not look like a jwt")
	}
	
	var err error
	var header map[string]interface{}
	err = decodeSegment(strArray[0], &header)
	if err != nil {
		return nil, err
	}
	if header["typ"] != "JWT" {
		return nil, errors.New("invalid jwt: type is not JWT")
	}
	if header["alg"] != "RS256" {
		return nil, errors.New("invalid jwt: algorithm is not RS256")
	}

	var claims map[string]interface{}
	err = decodeSegment(strArray[1], &claims)
	if err != nil {
		return nil, err
	}

	var signature []byte
	signature, err = base64.RawURLEncoding.DecodeString(strArray[2])
	if err != nil {
		return nil, err
	}

	var jwt = JWT{
		Header: header,
		Claims: claims,
		Signature: string(signature),
		// calculate and keep the SHA256 hash of the header and claims
		// this will be needed to verify the signature
		SHA256: sha256.Sum256([]byte(strArray[0] + "." + strArray[1])),
	}
	return &jwt, nil
}

func decodeSegment(str string, v interface{}) error {
	jsonStr, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonStr, &v)
	if err != nil {
		return err
	}
	return nil
}

func (jwt *JWT) Validate(JWKSEndpoint string, expectedClaims map[string]interface{}) error {
	err := jwt.ValidateClaims(expectedClaims)
	if err != nil {
		return err
	}
	err = jwt.ValidateSignature(JWKSEndpoint)
	if err != nil {
		return err
	}
	return nil
}

func (jwt *JWT) ValidateClaims(expectedClaims map[string]interface{}) error {
	for k, v := range expectedClaims {
		if (jwt.Claims[k] != v) {
			return errors.New("invalid token: claim " + k + " does not contain value " + v.(string))
		}
	}
	return nil
}

func (jwt *JWT) ValidateSignature(JWKSEndpoint string) error {
	// not implemented yet
	return nil
}