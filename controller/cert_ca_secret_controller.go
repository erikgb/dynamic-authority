package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/erikgb/dynamic-authority/controller/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// CASecretReconciler reconciles a CA Secret object
type CASecretReconciler struct {
	reconciler
	events chan event.GenericEvent
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;patch

// SetupWithManager sets up the controller with the Manager.
func (r *CASecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.events = make(chan event.GenericEvent)
	go func() {
		r.events <- event.GenericEvent{}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		Named("ca_secret").
		WatchesRawSource(r.secretSource(r.Opts.CASecret)).
		WatchesRawSource(
			source.Channel(
				r.events,
				handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []ctrl.Request {
					return []ctrl.Request{{NamespacedName: r.Opts.CASecret}}
				}),
			),
		).
		Complete(r)
}

func (r *CASecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	return ctrl.Result{}, r.reconcileSecret(ctx, req.NamespacedName)
}

func (r *CASecretReconciler) reconcileSecret(ctx context.Context, name types.NamespacedName) error {
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
	// Cert is included in CA bundle
	if !bytes.Equal(secret.Data[TLSCABundleKey], secret.Data[corev1.TLSCertKey]) {
		return nil
	}

	cert, pk, err := r.generateCA()
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

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// generateCA will regenerate a new CA.
func (d *CASecretReconciler) generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
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
