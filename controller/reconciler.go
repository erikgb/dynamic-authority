package controller

import (
	"time"

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

func (r reconciler) renewRequested(secret *corev1.Secret) bool {
	requestedAt, ok := secret.Annotations[RenewCertificateSecretAnnotation]
	if !ok {
		return false
	}
	requestedAtTime := &time.Time{}
	if err := requestedAtTime.UnmarshalText([]byte(requestedAt)); err != nil {
		return false
	}

	issuedAt, ok := secret.Annotations[IssuedCertificateSecretAnnotation]
	if !ok {
		return false
	}
	issuedAtTime := &time.Time{}
	if err := issuedAtTime.UnmarshalText([]byte(issuedAt)); err != nil {
		return false
	}

	return !issuedAtTime.After(*requestedAtTime)
}

func nowString() string {
	nowBytes, _ := time.Now().MarshalText()
	return string(nowBytes)
}
