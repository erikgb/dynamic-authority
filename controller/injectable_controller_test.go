package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Injectable Controller", Ordered, func() {
	var (
		caSecret types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "injectable-controller"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		secret := &corev1.Secret{}
		secret.Namespace = ns.Name
		secret.Name = "ca-secret"
		secret.Type = corev1.SecretTypeTLS
		secret.Labels = map[string]string{
			DynamicAuthoritySecretLabel: "true",
		}
		secret.Data = map[string][]byte{
			corev1.TLSCertKey:       []byte("TODO CA cert"),
			corev1.TLSPrivateKeyKey: []byte("TODO CA cert key"),
			TLSCABundleKey:          []byte("TODO CA bundle"),
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		caSecret = client.ObjectKeyFromObject(secret)

		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		controller := &InjectableReconciler{
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

	It("should inject CA bundle into VWC", func() {
		vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		vwc.Name = "test-vwc"
		vwc.Labels = map[string]string{
			WantInjectFromSecretNamespaceLabel: caSecret.Namespace,
			WantInjectFromSecretNameLabel:      caSecret.Name,
		}
		Expect(k8sClient.Create(ctx, vwc)).To(Succeed())
	})
})
