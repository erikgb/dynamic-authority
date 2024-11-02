package controller

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// InjectableReconciler injects CA bundle into resources
type InjectableReconciler struct {
	reconciler
	Injectable Injectable
}

// SetupWithManager sets up the controllers with the Manager.
func (r *InjectableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(strings.ToLower(r.Injectable.GroupVersionKind().Kind)).
		WatchesRawSource(r.secretSource(r.Opts.CASecret)).
		WatchesRawSource(
			source.Kind(
				r.Cache,
				newUnstructured(r.Injectable),
				handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, obj *unstructured.Unstructured) []ctrl.Request {
					return []ctrl.Request{{NamespacedName: types.NamespacedName{
						Namespace: r.Opts.Namespace,
						Name:      r.Opts.CASecret,
					}}}
				}),
				predicate.NewTypedPredicateFuncs(func(obj *unstructured.Unstructured) bool {
					return obj.GetLabels()[WantInjectFromSecretNamespaceLabel] == r.Opts.Namespace && obj.GetLabels()[WantInjectFromSecretNameLabel] == r.Opts.CASecret
				}))).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *InjectableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, r.reconcileInjectables(ctx, secret)
}

func (r *InjectableReconciler) reconcileInjectables(ctx context.Context, secret *corev1.Secret) error {
	objList := &unstructured.UnstructuredList{}
	objList.SetGroupVersionKind(r.Injectable.GroupVersionKind())
	if err := r.List(ctx, objList, client.MatchingLabels(map[string]string{
		WantInjectFromSecretNamespaceLabel: r.Opts.Namespace,
		WantInjectFromSecretNameLabel:      r.Opts.CASecret,
	})); err != nil {
		return err
	}

	caBundle := secret.Data[TLSCABundleKey]

	for _, obj := range objList.Items {
		ac, err := r.Injectable.InjectCA(&obj, caBundle)
		if err != nil {
			return err
		}

		if err := r.Patch(ctx, &obj, newApplyPatch(ac), client.ForceOwnership, fieldOwner); err != nil {
			return err
		}
	}

	return nil
}
