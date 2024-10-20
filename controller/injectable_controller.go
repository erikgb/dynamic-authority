package controller

import (
	"context"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	admissionregistrationv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// InjectableReconciler injects CA bundle into resources
type InjectableReconciler struct {
	client.Client
	Cache cache.Cache
	Opts  Options
}

// SetupWithManager sets up the controllers with the Manager.
func (r *InjectableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WatchesRawSource(
			source.Kind(
				r.Cache,
				&corev1.Secret{},
				&handler.TypedEnqueueRequestForObject[*corev1.Secret]{},
			),
		).
		Named("validating_webhook_configuration_ca_inject").
		WatchesRawSource(
			source.Kind(
				r.Cache,
				&admissionregistrationv1.ValidatingWebhookConfiguration{},
				handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, obj *admissionregistrationv1.ValidatingWebhookConfiguration) []ctrl.Request {
					if obj.GetLabels()[WantInjectFromSecretNamespaceLabel] == r.Opts.CASecret.Namespace &&
						obj.GetLabels()[WantInjectFromSecretNameLabel] == r.Opts.CASecret.Name {
						return []ctrl.Request{{NamespacedName: r.Opts.CASecret}}
					}
					return []ctrl.Request{}
				}),
			),
		).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;patch

func (r *InjectableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, r.reconcileInjectables(ctx, secret)
}

func (r *InjectableReconciler) reconcileInjectables(ctx context.Context, secret *corev1.Secret) error {
	objList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, objList, client.MatchingLabels(map[string]string{
		WantInjectFromSecretNamespaceLabel: r.Opts.CASecret.Namespace,
		WantInjectFromSecretNameLabel:      r.Opts.CASecret.Name,
	})); err != nil {
		return err
	}

	caBundle := secret.Data[TLSCABundleKey]
	clientConfig := admissionregistrationv1ac.WebhookClientConfig().
		WithCABundle(caBundle...)

	for _, obj := range objList.Items {
		ac := admissionregistrationv1ac.ValidatingWebhookConfiguration(obj.Name)
		for _, w := range obj.Webhooks {
			ac.WithWebhooks(
				admissionregistrationv1ac.ValidatingWebhook().
					WithName(w.Name).
					WithClientConfig(clientConfig),
			)
		}

		if err := r.Patch(ctx, &obj, newApplyPatch(ac), client.ForceOwnership, fieldOwner); err != nil {
			return err
		}
	}

	return nil
}
