package oidc

import "errors"

type TokenValidation struct {
	Token 			 string
	JWKSEndpoint 	 string
	ExpectedAudience string
	ExpectedIssuer 	 string
	ExpectedScope 	 string
}

func (tVal *TokenValidation) Validate() error {
	validations := []func() (s bool, msg string, err error){ 
		tVal.validateTokenIsJwt,
		tVal.validateTokenSignature,
		tVal.validateTokenExpiration,
		tVal.validateTokenAudience,
		tVal.validateTokenIssuer,
		tVal.validateTokenScope,
		tVal.validateTokenRevocation,
	}

	for _, v := range validations {
		success, msg, err := v()
		if err != nil {
			return err
		}
		if !success {
			return errors.New("invalid token: " + msg)
		}
	}
	return nil
}

func (tVal *TokenValidation) validateTokenIsJwt() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}

func (tVal *TokenValidation) validateTokenSignature() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}

func (tVal *TokenValidation) validateTokenExpiration() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}

func (tVal *TokenValidation) validateTokenAudience() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}

func (tVal *TokenValidation) validateTokenIssuer() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}

func (tVal *TokenValidation) validateTokenScope() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}

func (tVal *TokenValidation) validateTokenRevocation() (s bool, msg string, err error) {
	s = true
	return s, msg, err
}