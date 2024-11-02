package controller

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type reconciler struct {
	client.Client
	Cache cache.Cache
	Opts  Options
}

func (r reconciler) secretSource(predicates ...predicate.TypedPredicate[*corev1.Secret]) source.SyncingSource {
	return source.Kind(
		r.Cache,
		&corev1.Secret{},
		&handler.TypedEnqueueRequestForObject[*corev1.Secret]{},
		predicates...)
}
