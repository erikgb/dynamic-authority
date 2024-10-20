package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var _ = Describe("Injectable Controller", Ordered, func() {
	var (
		caSecret types.NamespacedName
		caBundle []byte
	)

	BeforeAll(func() {
		caBundle = []byte("TODO CA bundle")

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
			TLSCABundleKey:          caBundle,
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
		vwc.Webhooks = []admissionregistrationv1.ValidatingWebhook{
			newValidatingWebhookForTest("foo-webhook.cert-manager.io"),
			newValidatingWebhookForTest("bar-webhook.cert-manager.io"),
		}
		Expect(k8sClient.Create(ctx, vwc)).To(Succeed())

		Eventually(komega.Object(vwc)).Should(
			HaveField("Webhooks", HaveEach(
				HaveField("ClientConfig.CABundle", Equal(caBundle)),
			)),
		)
	})
})

func newValidatingWebhookForTest(name string) admissionregistrationv1.ValidatingWebhook {
	return admissionregistrationv1.ValidatingWebhook{
		Name:                    name,
		AdmissionReviewVersions: []string{"v1"},
		SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
		ClientConfig: admissionregistrationv1.WebhookClientConfig{
			URL: ptr.To("https://" + name),
		},
	}
}
