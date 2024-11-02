package controller

import (
	"context"
	"k8s.io/apimachinery/pkg/api/errors"
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
		WatchesRawSource(
			source.Kind(
				r.Cache,
				newUnstructured(r.Injectable),
				&handler.TypedEnqueueRequestForObject[*unstructured.Unstructured]{},
				predicate.NewTypedPredicateFuncs(func(obj *unstructured.Unstructured) bool {
					return obj.GetLabels()[WantInjectFromSecretNamespaceLabel] == r.Opts.Namespace && obj.GetLabels()[WantInjectFromSecretNameLabel] == r.Opts.CASecret
				}))).
		Complete(r)
}

func (r *InjectableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Opts.Namespace, Name: r.Opts.CASecret}, secret); err != nil {
		if errors.IsNotFound(err) {
			log.FromContext(ctx).V(1).Info("CA secret not yet found, requeueing request...")
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, r.reconcileInjectable(ctx, req, secret.Data[TLSCABundleKey])
}

func (r *InjectableReconciler) reconcileInjectable(ctx context.Context, req ctrl.Request, caBundle []byte) error {
	obj := newUnstructured(r.Injectable)
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return err
	}

	ac, err := r.Injectable.InjectCA(obj, caBundle)
	if err != nil {
		return err
	}

	if err := r.Patch(ctx, obj, newApplyPatch(ac), client.ForceOwnership, fieldOwner); err != nil {
		return err
	}

	return nil
}
