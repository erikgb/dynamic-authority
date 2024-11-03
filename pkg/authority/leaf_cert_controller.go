package authority

import (
	"context"

	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
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
		WatchesRawSource(r.secretSource(r.Opts.caSecretPredicate())).
		// Disable leader election since all replicas need a serving certificate
		WithOptions(controller.TypedOptions[ctrl.Request]{NeedLeaderElection: ptr.To(false)}).
		Complete(r)
}

func (r *LeafCertReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}
