/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// CASecretReconciler reconciles a CA Secret object
type CASecretReconciler struct {
	client.Client
	Cache cache.Cache
	Opts  Options

	events chan event.GenericEvent
}

// SetupWithManager sets up the controller with the Manager.
func (r *CASecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.events = make(chan event.GenericEvent)
	go func() {
		r.events <- event.GenericEvent{}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		Named("ca_secret").
		WatchesRawSource(
			source.Kind(
				r.Cache,
				&corev1.Secret{},
				&handler.TypedEnqueueRequestForObject[*corev1.Secret]{},
			),
		).
		WatchesRawSource(source.Channel(r.events, handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []ctrl.Request {
			return []ctrl.Request{{NamespacedName: r.Opts.CASecret}}
		}))).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;patch

func (r *CASecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	return ctrl.Result{}, r.reconcileCASecret(ctx, req.NamespacedName)
}

func (r *CASecretReconciler) reconcileCASecret(ctx context.Context, name types.NamespacedName) error {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, name, secret); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		secret.Namespace = name.Namespace
		secret.Name = name.Name
	}

	// TODO: Check if secret is up-to-date
	// Has valid cert + key
	// Cert is included in CA bundle
	dummyCert := []byte("TODO CA cert")
	if bytes.Equal(secret.Data[corev1.TLSCertKey], dummyCert) {
		return nil
	}

	data := map[string][]byte{
		corev1.TLSCertKey:       dummyCert,
		corev1.TLSPrivateKeyKey: []byte("TODO CA cert key"),
		TLSCABundleKey:          []byte("TODO CA bundle"),
	}
	ac := corev1ac.Secret(secret.Name, secret.Namespace).
		WithLabels(map[string]string{DynamicAuthoritySecretLabel: "true"}).
		WithType(corev1.SecretTypeTLS).
		WithData(data)

	return r.Patch(ctx, secret, newApplyPatch(ac), client.ForceOwnership, fieldOwner)
}
