package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

func randomInt(min, max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64()) + min
}

func pkceCodeVerifier(n int) string {
	if n < 32 || n > 96 {
		panic("Code verifier length before base64 encoding must be between 32 and 96 bytes")
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	// NoPadding is used to avoid '=' padding characters which are not accepted by the authorization server in the code_verifier parameter
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func pkceCodeChallenge(codeVerifier string) string {
	sha := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}
