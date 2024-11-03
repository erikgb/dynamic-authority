package controller

import (
	"crypto/tls"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/erikgb/dynamic-authority/pkg/authority"
)

var _ = Describe("Controller Integration Test", Ordered, func() {
	var (
		caSecretRef types.NamespacedName
		tlsConfig   *tls.Config
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "dynamic-authority"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caSecretRef = types.NamespacedName{
			Namespace: ns.Name,
			Name:      "ca-cert",
		}

		operator := &authority.ServingCertificateOperator{
			Options: authority.Options{
				Namespace: caSecretRef.Namespace,
				CASecret:  caSecretRef.Name,
				Injectables: []authority.Injectable{
					&authority.ValidatingWebhookCaBundleInject{},
				},
			},
		}

		servingCertificate := operator.ServingCertificate()

		tlsConfig = &tls.Config{}
		servingCertificate(tlsConfig)
		Expect(tlsConfig.GetCertificate).ToNot(BeNil())

		webhookInstallOptions := &testEnv.WebhookInstallOptions
		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
			WebhookServer: webhook.NewServer(webhook.Options{
				Host:    webhookInstallOptions.LocalServingHost,
				Port:    webhookInstallOptions.LocalServingPort,
				TLSOpts: []func(*tls.Config){servingCertificate},
			}),
		})
		Expect(err).ToNot(HaveOccurred())

		Expect(operator.SetupWithManager(k8sManager)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	It("should inject CA bundle into VWC", func() {
		vwc := authority.NewValidatingWebhookConfigurationForTest("test-vwc", caSecretRef)
		Expect(k8sClient.Create(ctx, vwc)).To(Succeed())

		Eventually(komega.Object(vwc)).Should(
			HaveField("Webhooks", HaveEach(
				HaveField("ClientConfig.CABundle", Not(BeEmpty())),
			)),
		)
	})

	It("should set serving certificate", func() {
		Eventually(func() (*tls.Certificate, error) {
			return tlsConfig.GetCertificate(nil)
		}).ShouldNot(BeNil())
	})
})
