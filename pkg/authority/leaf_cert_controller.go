package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/erikgb/dynamic-authority/internal/pki"
)

// LeafCertReconciler reconciles the leaf/serving certificate
type LeafCertReconciler struct {
	reconciler
	certificateHolder *CertificateHolder
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// SetupWithManager sets up the controller with the Manager.
func (r *LeafCertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("cert_leaf").
		WatchesRawSource(r.caSecretSource(&handler.TypedEnqueueRequestForObject[*corev1.Secret]{})).
		// Disable leader election since all replicas need a serving certificate
		WithOptions(controller.TypedOptions[ctrl.Request]{NeedLeaderElection: ptr.To(false)}).
		Complete(r)
}

func (r *LeafCertReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, r.reconcileSecret(ctx, req)
}

func (r *LeafCertReconciler) reconcileSecret(ctx context.Context, req ctrl.Request) error {
	caSecret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, caSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	caCertBytes := caSecret.Data[corev1.TLSCertKey]
	caPkBytes := caSecret.Data[corev1.TLSPrivateKeyKey]

	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return err
	}

	// create the certificate template to be signed
	template := &x509.Certificate{
		Version:            3,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          pk.Public(),
		DNSNames:           r.Opts.DNSNames,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	cert, err := Sign(r.Opts, template, caCertBytes, caPkBytes)
	if err != nil {
		return err
	}

	pkData, err := pki.EncodePrivateKey(pk)
	if err != nil {
		return err
	}

	certData, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return err
	}

	r.certificateHolder.SetCertificate(&tlsCert)
	return nil
}
