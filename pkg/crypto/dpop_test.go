package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateDpopProof(t *testing.T) {

	privateKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyRSA := &privateKeyRSA.PublicKey

	privateKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyECDSA := &privateKeyECDSA.PublicKey

	publicKeyEd25519, privateKeyEd25519, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name                  string
		privateKey            any
		publicKey             any
		method                string
		url                   string
		expectedSigningMethod jwt.SigningMethod
	}{
		{
			name:                  "create dpop header using rsa key",
			privateKey:            privateKeyRSA,
			publicKey:             publicKeyRSA,
			method:                "POST",
			url:                   "https://example.com",
			expectedSigningMethod: jwt.SigningMethodRS256,
		},
		{
			name:                  "create dpop header using ecdsa key",
			privateKey:            privateKeyECDSA,
			publicKey:             publicKeyECDSA,
			method:                "POST",
			url:                   "https://example.com",
			expectedSigningMethod: jwt.SigningMethodES256,
		},
		{
			name:                  "create dpop header using ed25519 key",
			privateKey:            privateKeyEd25519,
			publicKey:             publicKeyEd25519,
			method:                "POST",
			url:                   "https://example.com",
			expectedSigningMethod: jwt.SigningMethodEdDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// verify that CreateDpopProof does not return an error
			// and that the generated token is not empty
			got, err := CreateDpopProof(tt.privateKey, tt.publicKey, tt.method, tt.url)
			if err != nil {
				t.Errorf("CreateDpopProof() error = %v, wantErr %v", err, nil)
			}
			if got == "" {
				t.Errorf("CreateDpopProof() got = %v, want %v", got, "not empty")
			}

			// parse the token and verify the signing key type
			token, err := jwt.Parse(got, func(token *jwt.Token) (any, error) {
				switch token.Method.(type) {
				case *jwt.SigningMethodRSA:
					if tt.expectedSigningMethod != jwt.SigningMethodRS256 {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return publicKeyRSA, nil
				case *jwt.SigningMethodECDSA:
					if tt.expectedSigningMethod != jwt.SigningMethodES256 {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return publicKeyECDSA, nil
				case *jwt.SigningMethodEd25519:
					if tt.expectedSigningMethod != jwt.SigningMethodEdDSA {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return publicKeyEd25519, nil
				default:
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
			})
			if err != nil {
				t.Errorf("jwt.Parse() = %v, want %v", err, nil)
			}
			if token == nil {
				t.Errorf("token = %v, want %v", token, "not nil")
			}

			// verify that all parts of the token are populated
			if token.Header == nil {
				t.Errorf("token.Header = %v, want %v", token.Header, "not nil")
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				t.Errorf("token.Claims type = %v, want %v", token.Claims, "jwt.MapClaims")
			}
			if claims == nil {
				t.Errorf("token.Claims = %v, want %v", token.Claims, "not nil")
			}
			if token.Signature == nil {
				t.Errorf("token.Signature = %v, want %v", token.Signature, "not nil")
			}
		})
	}
}

func TestCreateDpopProofError(t *testing.T) {
	privateKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKeyRSA := &privateKeyRSA.PublicKey

	privateKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyECDSA := &privateKeyECDSA.PublicKey

	tests := []struct {
		name       string
		privateKey any
		publicKey  any
		method     string
		url        string
	}{
		{
			name:       "create dpop header using public key as private key",
			privateKey: publicKeyRSA,
			publicKey:  publicKeyRSA,
			method:     "POST",
			url:        "https://example.com",
		},
		{
			name:       "create dpop header using private key as public key",
			privateKey: privateKeyRSA,
			publicKey:  privateKeyRSA,
			method:     "POST",
			url:        "https://example.com",
		},
		{
			name:       "create dpop header with non-matching key types",
			privateKey: privateKeyRSA,
			publicKey:  publicKeyECDSA,
			method:     "POST",
			url:        "https://example.com",
		},
		{
			name:       "create dpop header using empty keys",
			privateKey: nil,
			publicKey:  nil,
			method:     "POST",
			url:        "https://example.com",
		},
		{
			name:       "create dpop header with invalid keys",
			privateKey: "1234",
			publicKey:  "1234",
			method:     "POST",
			url:        "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateDpopProof(tt.privateKey, tt.publicKey, tt.method, tt.url)
			if err == nil {
				t.Errorf("CreateDpopProof() error = %v, wantErr %v", err, "not nil")
			}
			if got != "" {
				t.Errorf("CreateDpopProof() got = %v, want %v", got, "empty")
			}
		})
	}
}

func TestConstructDpopToken(t *testing.T) {

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	tests := []struct {
		name          string
		jwk           any
		alg           string
		jti           string
		method        string
		url           string
		signingMethod jwt.SigningMethod
	}{
		{
			name:          "generate valid dpop token",
			jwk:           convertPublicKeyToRsaJwk(publicKey),
			alg:           rsaAlgorithmString(publicKey),
			jti:           generateJTI(),
			method:        "POST",
			url:           "https://example.com",
			signingMethod: jwt.SigningMethodRS256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := constructDpopToken(tt.jwk, tt.alg, tt.jti, tt.method, tt.url, tt.signingMethod)
			if got.Header == nil {
				t.Errorf("got.Header = %v, want %v", got.Header, "not nil")
			}
			if got.Header["alg"] != tt.alg {
				t.Errorf("got.Header[\"alg\"] = %v, want %v", got.Header["alg"], tt.alg)
			}
			if got.Header["typ"] != "dpop+jwt" {
				t.Errorf("got.Header[\"typ\"] = %v, want %v", got.Header["typ"], "dpop+jwt")
			}
			if got.Header["jwk"] != tt.jwk {
				t.Errorf("got.Header[\"jwk\"] = %v, want %v", got.Header["jwk"], tt.jwk)
			}
			if got.Claims == nil {
				t.Errorf("got.Claims = %v, want %v", got.Claims, "not nil")
			}
			claims, ok := got.Claims.(jwt.MapClaims)
			if !ok {
				t.Errorf("got.Claims = %v, want %v", got.Claims, "jwt.MapClaims")
			}
			if claims["jti"] != tt.jti {
				t.Errorf("claims\"jti\"] = %v, want %v", claims["jti"], tt.jti)
			}
			if claims["htm"] != tt.method {
				t.Errorf("claims[\"htm\"] = %v, want %v", claims["htm"], tt.method)
			}
			if claims["htu"] != tt.url {
				t.Errorf("claims[\"htu\"] = %v, want %v", claims["htu"], tt.url)
			}
			if claims["iat"] == nil {
				t.Errorf("claims[\"iat\"] = %v, want %v", claims["iat"], "not nil")
			}
			if got.Method != tt.signingMethod {
				t.Errorf("got.Method = %v, want %v", got.Method, tt.signingMethod)
			}
			signingString, _ := got.SigningString()
			if signingString == "" {
				t.Errorf("got.SigningString() = %v, want %v", signingString, "not empty")
			}
		})
	}
}

func TestEcdsaAlgorithmString(t *testing.T) {

	privateKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey256 := &privateKey256.PublicKey

	privateKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	publicKey384 := &privateKey384.PublicKey

	privateKey512, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	publicKey512 := &privateKey512.PublicKey

	tests := []struct {
		name     string
		key      *ecdsa.PublicKey
		expected string
	}{
		{
			name:     "valid 256-bit ecdsa key",
			key:      publicKey256,
			expected: "ES256",
		},
		{
			name:     "valid 384-bit ecdsa key",
			key:      publicKey384,
			expected: "ES384",
		},
		{
			name:     "valid 521-bit ecdsa key",
			key:      publicKey512,
			expected: "ES512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ecdsaAlgorithmString(tt.key)
			if got != tt.expected {
				t.Errorf("ecdsaAlgorithmString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRsaAlgorithmString(t *testing.T) {

	privateKey256, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey256 := &privateKey256.PublicKey

	privateKey384, _ := rsa.GenerateKey(rand.Reader, 3072)
	publicKey384 := &privateKey384.PublicKey

	privateKey512, _ := rsa.GenerateKey(rand.Reader, 4096)
	publicKey512 := &privateKey512.PublicKey

	tests := []struct {
		name     string
		key      *rsa.PublicKey
		expected string
	}{
		{
			name:     "valid 2048-bit rsa key",
			key:      publicKey256,
			expected: "RS256",
		},
		{
			name:     "valid 3072-bit rsa key",
			key:      publicKey384,
			expected: "RS384",
		},
		{
			name:     "valid 4096-bit rsa key",
			key:      publicKey512,
			expected: "RS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rsaAlgorithmString(tt.key)
			if got != tt.expected {
				t.Errorf("rsaAlgorithmString() = %v, want %v", got, tt.expected)
			}
		})
	}
}
