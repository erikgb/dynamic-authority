package authority

import (
	"context"
	"crypto/tls"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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

	certificate, err := tls.X509KeyPair(caSecret.Data[corev1.TLSCertKey], caSecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return err
	}

	r.certificateHolder.SetCertificate(&certificate)
	return nil
}
