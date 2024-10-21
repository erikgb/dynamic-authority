package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var _ = Describe("Injectable Controller", Ordered, func() {
	var (
		caSecret    *corev1.Secret
		caSecretRef types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "injectable-controller"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caSecret = &corev1.Secret{}
		caSecret.Namespace = ns.Name
		caSecret.Name = "ca-cert"
		caSecret.Type = corev1.SecretTypeTLS
		caSecret.Labels = map[string]string{
			DynamicAuthoritySecretLabel: "true",
		}
		caSecret.Data = map[string][]byte{
			corev1.TLSCertKey:       []byte("TODO CA cert injectable"),
			corev1.TLSPrivateKeyKey: []byte("TODO CA cert key injectable"),
			TLSCABundleKey:          []byte("TODO CA bundle injectable"),
		}
		Expect(k8sClient.Create(ctx, caSecret)).To(Succeed())
		caSecretRef = client.ObjectKeyFromObject(caSecret)

		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		controller := &InjectableReconciler{
			reconciler: reconciler{
				Client: k8sManager.GetClient(),
				Cache:  k8sManager.GetCache(),
				Opts:   Options{CASecret: caSecretRef},
			},
		}
		Expect(controller.SetupWithManager(k8sManager)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	It("should inject CA bundle into VWC", func() {
		vwc := NewValidatingWebhookConfigurationForTest("test-vwc", caSecretRef)
		Expect(k8sClient.Create(ctx, vwc)).To(Succeed())

		Eventually(komega.Object(vwc)).Should(
			HaveField("Webhooks", HaveEach(
				HaveField("ClientConfig.CABundle", Equal(caSecret.Data[TLSCABundleKey])),
			)),
		)
	})
})
