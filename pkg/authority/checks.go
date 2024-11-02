package authority

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/erikgb/dynamic-authority/internal/pki"
)

func SecretPublicKeysDiffer(secret *corev1.Secret) (bool, error) {
	pk, err := pki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return true, fmt.Errorf("secret contains invalid private key data: %w", err)
	}
	x509Cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return true, fmt.Errorf("secret contains an invalid certificate: %w", err)
	}

	equal, err := pki.PublicKeysEqual(x509Cert.PublicKey, pk.Public())
	if err != nil {
		return true, fmt.Errorf("secret contains an invalid key-pair: %w", err)
	}
	if !equal {
		return true, errors.New("secret contains a private key that does not match the certificate")
	}

	return false, nil
}
