package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GeneratePKCECodeVerifier() (string, error) {
	b := make([]byte, 96) // 96 bytes is the maximum length for a code verifier
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read from random to generate PKCE code verifier %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func GeneratePKCECodeChallenge(codeVerifier string) string {
	sha := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}
