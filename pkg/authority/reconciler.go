package authority

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type reconciler struct {
	client.Client
	Cache cache.Cache
	Opts  Options
}

func (r reconciler) caSecretSource(handler handler.TypedEventHandler[*corev1.Secret, reconcile.Request]) source.SyncingSource {
	return source.Kind(
		r.Cache,
		&corev1.Secret{},
		handler,
		predicate.NewTypedPredicateFuncs[*corev1.Secret](func(obj *corev1.Secret) bool {
			return obj.Namespace == r.Opts.Namespace && obj.Name == r.Opts.CASecret
		}))
}
