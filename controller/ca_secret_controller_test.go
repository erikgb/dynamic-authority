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
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
)

var _ = Describe("CA Secret Controller", func() {
	var (
		secret *corev1.Secret
	)

	BeforeEach(func() {
		secret = &corev1.Secret{}
		secret.Namespace = caSecret.Namespace
		secret.Name = caSecret.Name
	})

	It("should create a CA secret", func() {
		Eventually(komega.Object(secret)).Should(
			HaveField("Labels", HaveKeyWithValue(DynamicAuthoritySecretLabel, "true")))
		Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
		Expect(secret.Data).To(Equal(map[string][]byte{
			corev1.TLSCertKey:       []byte("TODO CA cert"),
			corev1.TLSPrivateKeyKey: []byte("TODO CA cert key"),
			TLSCABundleKey:          []byte("TODO CA bundle"),
		}))
	})
})
