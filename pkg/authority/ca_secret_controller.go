package authority

import (
	"context"
	"crypto"
	"crypto/x509"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/erikgb/dynamic-authority/internal/pki"
)

// CASecretReconciler reconciles a CA Secret object
type CASecretReconciler struct {
	reconciler
	events chan event.TypedGenericEvent[*corev1.Secret]
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;patch

// SetupWithManager sets up the controller with the Manager.
func (r *CASecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.events = make(chan event.TypedGenericEvent[*corev1.Secret])
	go func() {
		obj := &corev1.Secret{}
		obj.Namespace = r.Opts.Namespace
		obj.Name = r.Opts.CASecret
		r.events <- event.TypedGenericEvent[*corev1.Secret]{Object: obj}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		Named("cert_ca_secret").
		WatchesRawSource(r.caSecretSource(&handler.TypedEnqueueRequestForObject[*corev1.Secret]{})).
		WatchesRawSource(
			source.Channel(
				r.events,
				&handler.TypedEnqueueRequestForObject[*corev1.Secret]{}),
		).
		Complete(r)
}

func (r *CASecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, r.reconcileSecret(ctx, req)
}

func (r *CASecretReconciler) reconcileSecret(ctx context.Context, req ctrl.Request) error {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		// Secret does not exist - let's create it
		secret.Namespace = req.Namespace
		secret.Name = req.Name
	}

	generate, cert, pk := r.needsGenerate(secret)

	if generate || secret.Annotations[RenewCertificateSecretAnnotation] != secret.Annotations[RenewHandledCertificateSecretAnnotation] {
		var err error
		cert, pk, err = generateCA(r.Opts)
		if err != nil {
			return err
		}
	}

	certBytes, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}
	pkBytes, err := pki.EncodePrivateKey(pk)
	if err != nil {
		return err
	}

	caBundleBytes, err := r.reconcileCABundle(secret.Data[TLSCABundleKey], cert)
	if err != nil {
		log.FromContext(ctx).V(1).Error(err, "when reconciling CA bundle")
		caBundleBytes = certBytes
	}

	ac := corev1ac.Secret(secret.Name, secret.Namespace).
		WithLabels(map[string]string{
			DynamicAuthoritySecretLabel: "true",
		}).
		WithType(corev1.SecretTypeTLS).
		WithData(map[string][]byte{
			corev1.TLSCertKey:       certBytes,
			corev1.TLSPrivateKeyKey: pkBytes,
			TLSCABundleKey:          caBundleBytes,
		})

	if v, ok := secret.Annotations[RenewCertificateSecretAnnotation]; ok {
		ac.WithAnnotations(map[string]string{
			RenewHandledCertificateSecretAnnotation: v,
		})
	}

	return r.Patch(ctx, secret, newApplyPatch(ac), client.ForceOwnership, fieldOwner)
}

func (r *CASecretReconciler) reconcileCABundle(caBundleBytes []byte, caCert *x509.Certificate) ([]byte, error) {
	certPool := pki.NewCertPool(pki.WithFilteredExpiredCerts(true))

	if len(caBundleBytes) > 0 {
		caBundle, err := pki.DecodeX509CertificateSetBytes(caBundleBytes)
		if err != nil {
			return nil, err
		}
		for _, c := range caBundle {
			certPool.AddCert(c)
		}
	}

	certPool.AddCert(caCert)

	return []byte(certPool.PEM()), nil
}

func (r *CASecretReconciler) needsGenerate(secret *corev1.Secret) (bool, *x509.Certificate, crypto.Signer) {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return true, nil, nil
	}
	pk, err := pki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return true, nil, nil
	}

	equal, err := pki.PublicKeysEqual(cert.PublicKey, pk.Public())
	if !equal || err != nil {
		return true, nil, nil
	}

	// TODO: Trigger renew check due
	return false, cert, pk
}
