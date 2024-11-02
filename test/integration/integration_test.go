package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	controller "github.com/erikgb/dynamic-authority/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var _ = Describe("Controller Integration Test", Ordered, func() {
	var (
		caSecretRef types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "dynamic-authority"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caSecretRef = types.NamespacedName{
			Namespace: ns.Name,
			Name:      "ca-cert",
		}

		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		opts := controller.Options{
			Namespace: caSecretRef.Namespace,
			CASecret:  caSecretRef.Name,
			Injectables: []controller.Injectable{
				&controller.ValidatingWebhookCaBundleInject{},
			},
		}
		Expect(controller.SetupWithManager(k8sManager, opts)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	It("should inject CA bundle into VWC", func() {
		vwc := controller.NewValidatingWebhookConfigurationForTest("test-vwc", caSecretRef)
		Expect(k8sClient.Create(ctx, vwc)).To(Succeed())

		Eventually(komega.Object(vwc)).Should(
			HaveField("Webhooks", HaveEach(
				HaveField("ClientConfig.CABundle", Not(BeEmpty())),
			)),
		)
	})
})
