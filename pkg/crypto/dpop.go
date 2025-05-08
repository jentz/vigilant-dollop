package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ecdsaJWK struct {
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
	Kty string `json:"kty"`
}

type rsaJWK struct {
	Exponent string `json:"e"`
	Modulus  string `json:"n"`
	Kty      string `json:"kty"`
}

type ed25519JWK struct {
	PublicKey string `json:"x"`
	Kty       string `json:"kty"`
}

func CreateDpopProof(privateKey any, publicKey any, method string, url string) (string, error) {

	jwk, err := mapPublicKeyToJwK(publicKey)
	if err != nil {
		return "", fmt.Errorf("error mapping key to JWK: %w", err)
	}

	alg, err := getAlgorithm(publicKey)
	if err != nil {
		return "", fmt.Errorf("error getting key algorithm: %w", err)
	}

	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": alg,
		"jwk": jwk,
	}

	claims := jwt.MapClaims{
		"jti": generateJTI(),
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
	}

	var token *jwt.Token

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	case *rsa.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case ed25519.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	default:
		return "", fmt.Errorf("unsupported private key type: %T", k)
	}

	token.Header = header

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing DPoP JWT: %w", err)
	}

	return signedToken, nil
}

func generateJTI() string {
	randomBytes := make([]byte, 30)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal(err)
	}
	hash := sha256.Sum256(randomBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func mapPublicKeyToJwK(v any) (any, error) {
	switch v := v.(type) {
	case *ecdsa.PublicKey:
		// Calculate the size of the byte array representation of an elliptic curve coordinate
		// and ensure that the byte array representation of the key is padded correctly.
		bits := v.Curve.Params().BitSize
		keyCurveBytesSize := bits/8 + bits%8

		return &ecdsaJWK{
			X:   base64.RawURLEncoding.EncodeToString(v.X.FillBytes(make([]byte, keyCurveBytesSize))),
			Y:   base64.RawURLEncoding.EncodeToString(v.Y.FillBytes(make([]byte, keyCurveBytesSize))),
			Crv: v.Curve.Params().Name,
			Kty: "EC",
		}, nil
	case *rsa.PublicKey:
		return &rsaJWK{
			Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(v.E)).Bytes()),
			Modulus:  base64.RawURLEncoding.EncodeToString(v.N.Bytes()),
			Kty:      "RSA",
		}, nil
	case ed25519.PublicKey:
		return &ed25519JWK{
			PublicKey: base64.RawURLEncoding.EncodeToString(v),
			Kty:       "OKP",
		}, nil
	}
	log.Fatalf("unsupported public key type: %T", v)
	return nil, errors.New("unsupported key algorithm")
}

func getAlgorithm(publicKey any) (string, error) {
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		switch bits := k.N.BitLen(); {
		case bits >= 4096:
			return "RS512", nil
		case bits >= 3072:
			return "RS384", nil
		case bits >= 2048:
			return "RS256", nil
		default:
			return "", fmt.Errorf("unsupported RSA key size: %d bits", bits)
		}
	case *ecdsa.PublicKey:
		bitSize := k.Params().BitSize
		switch bitSize {
		case 256:
			return "ES256", nil
		case 384:
			return "ES384", nil
		case 521:
			return "ES512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve bit size: %d", bitSize)
		}
	case ed25519.PublicKey:
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", k)
	}
}
