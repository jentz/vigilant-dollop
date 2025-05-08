package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func ReadPublicKeyFromFile(filePath string) (any, error) {
	// Read the public key from the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("failed to decode PEM block for public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}

	return key, nil
}

func ReadPrivateKeyFromFile(filePath string) (any, error) {
	// Read the private key from the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	// Decode the PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("failed to decode PEM block for private key")
	}

	var key any

	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}

	return key, nil
}
