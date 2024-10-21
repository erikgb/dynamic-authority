package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/erikgb/dynamic-authority/controller/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// LeafCertSecretReconciler reconciles a leaf certificate Secret object
type LeafCertSecretReconciler struct {
	reconciler
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;patch

// SetupWithManager sets up the controller with the Manager.
func (r *LeafCertSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("cert_leaf_secret").
		WatchesRawSource(r.secretSource(r.Opts.LeafSecret)).
		WatchesRawSource(source.Kind(
			r.Cache,
			&corev1.Secret{},
			handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, obj *corev1.Secret) []ctrl.Request {
				return []ctrl.Request{{NamespacedName: r.Opts.LeafSecret}}
			}),
			predicate.NewTypedPredicateFuncs[*corev1.Secret](func(obj *corev1.Secret) bool {
				return obj.Namespace == r.Opts.CASecret.Namespace && obj.Name == r.Opts.CASecret.Name
			}))).
		Complete(r)
}

func (r *LeafCertSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	return ctrl.Result{}, r.reconcileSecret(ctx, req.NamespacedName)
}

func (r *LeafCertSecretReconciler) reconcileSecret(ctx context.Context, name types.NamespacedName) error {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, name, secret); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		// Secret does not exist - let's create it
		secret.Namespace = name.Namespace
		secret.Name = name.Name
	}

	// TODO: Check if secret is up-to-date
	// Has valid cert + key
	if !bytes.Equal(secret.Data[TLSCABundleKey], secret.Data[corev1.TLSCertKey]) {
		return nil
	}

	cert, pk, err := r.regenerateCertificate()
	if err != nil {
		return err
	}

	certBytes, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}
	pkBytes, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		return err
	}

	data := map[string][]byte{
		corev1.TLSCertKey:       certBytes,
		corev1.TLSPrivateKeyKey: pkBytes,
		// TODO: Reconcile CA bundle correctly
		TLSCABundleKey: certBytes,
	}
	ac := corev1ac.Secret(secret.Name, secret.Namespace).
		WithLabels(map[string]string{DynamicAuthoritySecretLabel: "true"}).
		WithType(corev1.SecretTypeTLS).
		WithData(data)

	return r.Patch(ctx, secret, newApplyPatch(ac), client.ForceOwnership, fieldOwner)
}

// generateCA will regenerate and store a new CA.
// If the provided Secret is nil, a new secret resource will be Created.
// Otherwise, the provided resource will be modified and Updated.
func (d *LeafCertSecretReconciler) regenerateCertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return nil, nil, err
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
		NotAfter:  time.Now().Add(d.Opts.CADuration),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	}
	// self sign the root CA
	_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)

	return cert, pk, err
}
