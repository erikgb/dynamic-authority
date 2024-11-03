package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/erikgb/dynamic-authority/internal/pki"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// generateCA will regenerate a new CA.
func generateCA(opts Options) (*x509.Certificate, crypto.Signer, error) {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return nil, nil, err
	}

	duration := opts.CADuration
	if duration == 0 {
		duration = 7 * 24 * time.Hour
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.ECDSA,
		Subject: pkix.Name{
			CommonName: "cert-manager-dynamic-ca",
		},
		IsCA:      true,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(duration),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	}
	// self sign the root CA
	_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)

	return cert, pk, err
}

var (
	ErrCertNotAvailable = errors.New("no tls.Certificate available")
)

type CertificateHolder struct {
	certP atomic.Pointer[tls.Certificate]
}

func (h *CertificateHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.certP.Load()
	if cert == nil {
		return nil, ErrCertNotAvailable
	}
	return cert, nil
}

func (h *CertificateHolder) SetCertificate(cert *tls.Certificate) {
	h.certP.Store(cert)
}
