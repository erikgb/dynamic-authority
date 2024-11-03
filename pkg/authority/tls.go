package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/erikgb/dynamic-authority/internal/pki"
)

// Sign will sign the given certificate template using the current version of
// the managed CA.
// It will automatically set the NotBefore and NotAfter times appropriately.
func Sign(opts Options, template *x509.Certificate, currentCertData []byte, currentPrivateKeyData []byte) (*x509.Certificate, error) {
	// tls.X509KeyPair performs a number of verification checks against the
	// keypair, so we run it to verify the certificate and private key are
	// valid.
	_, err := tls.X509KeyPair(currentCertData, currentPrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed verifying CA keypair: %v", err)
	}

	caCert, err := pki.DecodeX509CertificateBytes(currentCertData)
	if err != nil {
		return nil, fmt.Errorf("failed decoding CA certificate: %v", err)
	}

	caPk, err := pki.DecodePrivateKeyBytes(currentPrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed decoding CA private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template.Version = 3
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(opts.LeafDuration)
	// explicitly handle the case of the root CA certificate being expired
	if caCert.NotAfter.Before(template.NotBefore) {
		return nil, fmt.Errorf("internal error: CA certificate has expired, try again later")
	}
	// don't allow leaf certificates to be valid longer than their parents
	if caCert.NotAfter.Before(template.NotAfter) {
		template.NotAfter = caCert.NotAfter
	}

	_, cert, err := pki.SignCertificate(template, caCert, template.PublicKey.(crypto.PublicKey), caPk)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

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
