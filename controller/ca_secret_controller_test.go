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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
)

var _ = Describe("CA Secret Controller", Ordered, func() {
	var (
		secret   *corev1.Secret
		caSecret types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "ca-secret-controller"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caSecret = types.NamespacedName{
			Namespace: ns.Name,
			Name:      "ca-secret",
		}

		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
		})
		Expect(err).ToNot(HaveOccurred())

		controller := &CASecretReconciler{
			Client: k8sManager.GetClient(),
			Cache:  k8sManager.GetCache(),
			Opts:   Options{CASecret: caSecret},
		}
		Expect(controller.SetupWithManager(k8sManager)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	BeforeEach(func() {
		secret = &corev1.Secret{}
		secret.Namespace = caSecret.Namespace
		secret.Name = caSecret.Name
	})

	It("should create CA secret on startup", func() {
		assertCASecret(secret)
	})

	It("should recreate CA secret if it's deleted", func() {
		Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		assertCASecret(secret)
	})

	It("should renew CA if CA secret is modified", func() {
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			corev1.TLSCertKey:       []byte("foo"),
			corev1.TLSPrivateKeyKey: []byte("bar"),
		}
		Expect(k8sClient.Update(ctx, secret)).To(Succeed())
		assertCASecret(secret)
	})
})

func assertCASecret(secret *corev1.Secret) {
	Eventually(komega.Object(secret)).Should(And(
		HaveField("Labels", HaveKeyWithValue(DynamicAuthoritySecretLabel, "true")),
		HaveField("Type", Equal(corev1.SecretTypeTLS)),
		HaveField("Data", Equal(map[string][]byte{
			corev1.TLSCertKey:       []byte("TODO CA cert"),
			corev1.TLSPrivateKeyKey: []byte("TODO CA cert key"),
			TLSCABundleKey:          []byte("TODO CA bundle"),
		})),
	))
}
