package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ReadPEMBlockFromFile(filePath string) (*pem.Block, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return block, nil
}

func ParsePublicKeyPEMBlock(block *pem.Block) (any, error) {
	if block == nil {
		return nil, fmt.Errorf("no PEM block provided")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func ParsePrivateKeyPEMBlock(block *pem.Block) (any, error) {
	if block == nil {
		return nil, fmt.Errorf("no PEM block provided")
	}

	var key any
	var err error
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
		return nil, err
	}

	return key, nil
}
