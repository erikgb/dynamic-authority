package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	// ECCurve256 represents a secp256r1 / prime256v1 / NIST P-256 ECDSA key.
	ECCurve256 = 256
	// ECCurve384 represents a secp384r1 / NIST P-384 ECDSA key.
	ECCurve384 = 384
	// ECCurve521 represents a secp521r1 / NIST P-521 ECDSA key.
	ECCurve521 = 521
)

// GenerateECPrivateKey will generate an ECDSA private key of the given size.
// It can be used to generate 256, 384 and 521 sized keys.
func GenerateECPrivateKey(keySize int) (*ecdsa.PrivateKey, error) {
	var ecCurve elliptic.Curve

	switch keySize {
	case ECCurve256:
		ecCurve = elliptic.P256()
	case ECCurve384:
		ecCurve = elliptic.P384()
	case ECCurve521:
		ecCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ecdsa key size specified: %d", keySize)
	}

	return ecdsa.GenerateKey(ecCurve, rand.Reader)
}

// EncodePKCS8PrivateKey will marshal a private key into x509 PEM format.
func EncodePKCS8PrivateKey(pk *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}

	return pem.EncodeToMemory(block), nil
}
