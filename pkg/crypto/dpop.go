package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

	var jwk any
	var alg string
	var jwtSigningMethod jwt.SigningMethod

	switch k := publicKey.(type) {

	case *ecdsa.PublicKey:
		if _, ok := privateKey.(*ecdsa.PrivateKey); !ok {
			return "", fmt.Errorf("private key type does not match public key type")
		}
		jwk = convertPublicKeyToEcdsaJwk(publicKey.(*ecdsa.PublicKey))
		alg = ecdsaAlgorithmString(publicKey.(*ecdsa.PublicKey))
		jwtSigningMethod = jwt.SigningMethodES256

	case *rsa.PublicKey:
		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			return "", fmt.Errorf("private key type does not match public key type")
		}
		jwk = convertPublicKeyToRsaJwk(publicKey.(*rsa.PublicKey))
		alg = rsaAlgorithmString(publicKey.(*rsa.PublicKey))
		jwtSigningMethod = jwt.SigningMethodRS256

	case ed25519.PublicKey:
		if _, ok := privateKey.(ed25519.PrivateKey); !ok {
			return "", fmt.Errorf("private key type does not match public key type")
		}
		jwk = convertPublicKeyToEd25519Jwk(publicKey.(ed25519.PublicKey))
		alg = ed25519AlgorithmString()
		jwtSigningMethod = jwt.SigningMethodEdDSA

	default:
		return "", fmt.Errorf("unsupported public key type: %T", k)
	}

	token := constructDpopToken(jwk, alg, generateJTI(), method, url, jwtSigningMethod)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing DPoP JWT: %w", err)
	}

	return signedToken, nil
}

func constructDpopToken(jwk any, alg string, jti string, method string, url string, jwtSigningMethod jwt.SigningMethod) *jwt.Token {
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": alg,
		"jwk": jwk,
	}

	claims := jwt.MapClaims{
		"jti": jti,
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwtSigningMethod, claims)
	token.Header = header

	return token
}

func generateJTI() string {
	randomBytes := make([]byte, 30)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(randomBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func convertPublicKeyToEcdsaJwk(k *ecdsa.PublicKey) any {
	// Calculate the size of the byte array representation of an elliptic curve coordinate
	// and ensure that the byte array representation of the key is padded correctly.
	bits := k.Curve.Params().BitSize
	keyCurveBytesSize := bits/8 + bits%8

	return &ecdsaJWK{
		X:   base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, keyCurveBytesSize))),
		Y:   base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, keyCurveBytesSize))),
		Crv: k.Curve.Params().Name,
		Kty: "EC",
	}
}

func convertPublicKeyToRsaJwk(k *rsa.PublicKey) any {
	return &rsaJWK{
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		Modulus:  base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		Kty:      "RSA",
	}
}

func convertPublicKeyToEd25519Jwk(k ed25519.PublicKey) any {
	return &ed25519JWK{
		PublicKey: base64.RawURLEncoding.EncodeToString(k),
		Kty:       "OKP",
	}
}

func ecdsaAlgorithmString(publicKey *ecdsa.PublicKey) string {
	switch publicKey.Params().BitSize {
	case 256:
		return "ES256"
	case 384:
		return "ES384"
	case 521:
		return "ES512"
	default:
		return ""
	}
}

func rsaAlgorithmString(publicKey *rsa.PublicKey) string {
	switch bits := publicKey.N.BitLen(); {
	case bits >= 4096:
		return "RS512"
	case bits >= 3072:
		return "RS384"
	case bits >= 2048:
		return "RS256"
	default:
		return ""
	}
}

func ed25519AlgorithmString() string {
	return "EdDSA"
}
