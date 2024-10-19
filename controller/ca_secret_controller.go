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
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// CASecretReconciler reconciles a CA Secret object
type CASecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

func (r *CASecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		// Resource could have been deleted after reconcile request, and thus not found.
		return ctrl.Result{}, ignoreErr(err, errors.IsNotFound)
	}

	// TODO: Check if secret is up-to-date
	if len(secret.Data[corev1.TLSCertKey]) > 0 {
		return ctrl.Result{}, nil
	}

	data := map[string][]byte{
		corev1.TLSCertKey:       []byte("TODO CA cert"),
		corev1.TLSPrivateKeyKey: []byte("TODO CA cert key"),
		TLSCABundleKey:          []byte("TODO CA bundle"),
	}
	ac := corev1ac.Secret(req.Name, req.Namespace).
		WithData(data)

	return ctrl.Result{}, r.Patch(ctx, secret, newApplyPatch(ac), client.ForceOwnership, fieldOwner)
}

// SetupWithManager sets up the controller with the Manager.
func (r *CASecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// TODO: Tune watch/cache
		For(&corev1.Secret{}, builder.WithPredicates(predicate.NewPredicateFuncs(byLabelFilter(DynamicAuthoritySecretLabel, "true")))).
		Complete(r)
}

var byLabelFilter = func(key, value string) func(object client.Object) bool {
	return func(object client.Object) bool {
		return object.GetLabels()[key] == value
	}
}
