package authority

import (
	"crypto/tls"
	"errors"
	"sync/atomic"
)

var (
	ErrNotAvailable = errors.New("no tls.Certificate available")
)

type CertificateHolder struct {
	certP atomic.Pointer[tls.Certificate]
}

func (h *CertificateHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.certP.Load()
	if cert == nil {
		return nil, ErrNotAvailable
	}
	return cert, nil
}

func (h *CertificateHolder) SetCertificate(cert *tls.Certificate) {
	h.certP.Store(cert)
}
