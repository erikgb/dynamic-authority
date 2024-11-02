package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/erikgb/dynamic-authority/controller/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var _ = Describe("CA Secret Controller", Ordered, func() {
	var (
		caSecret    *corev1.Secret
		caSecretRef types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "cert-ca-secret-controller"
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

		controller := &CASecretReconciler{
			reconciler: reconciler{
				Client: k8sManager.GetClient(),
				Cache:  k8sManager.GetCache(),
				Opts: Options{
					Namespace: caSecretRef.Namespace,
					CASecret:  caSecretRef.Name,
				}}}
		Expect(controller.SetupWithManager(k8sManager)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	BeforeEach(func() {
		caSecret = &corev1.Secret{}
		caSecret.Namespace = caSecretRef.Namespace
		caSecret.Name = caSecretRef.Name
	})

	It("should create Secret on startup", func() {
		assertCASecret(caSecret)
	})

	It("should recreate Secret if it's deleted", func() {
		Expect(k8sClient.Delete(ctx, caSecret)).To(Succeed())
		assertCASecret(caSecret)
	})

	It("should issue certificate if Secret is modified", func() {
		caSecret.Type = corev1.SecretTypeTLS
		caSecret.Data = map[string][]byte{
			corev1.TLSCertKey:       []byte("foo"),
			corev1.TLSPrivateKeyKey: []byte("bar"),
		}
		Expect(k8sClient.Update(ctx, caSecret)).To(Succeed())
		assertCASecret(caSecret)
	})

	It("should retain old CA if CA is rotated", func() {
		assertCASecret(caSecret)

		caBundleCerts, err := pki.DecodeX509CertificateSetBytes(caSecret.Data[TLSCABundleKey])
		Expect(err).ToNot(HaveOccurred())
		Expect(caBundleCerts).To(HaveLen(1))

		certBytes := caSecret.Data[corev1.TLSCertKey]

		Consistently(komega.Object(caSecret)).Should(
			HaveField("Data", HaveKeyWithValue(corev1.TLSCertKey, Equal(certBytes))),
		)

		By("requesting a renewal")
		caSecret.Annotations[RenewCertificateSecretAnnotation] = nowString()
		Expect(k8sClient.Update(ctx, caSecret)).To(Succeed())

		Eventually(komega.Object(caSecret)).Should(
			HaveField("Data", HaveKeyWithValue(corev1.TLSCertKey, Not(Equal(certBytes)))),
		)
		assertCASecret(caSecret)

		certBytes = caSecret.Data[corev1.TLSCertKey]
		Consistently(komega.Object(caSecret)).Should(
			HaveField("Data", HaveKeyWithValue(corev1.TLSCertKey, Equal(certBytes))),
		)

		caBundleCerts, err = pki.DecodeX509CertificateSetBytes(caSecret.Data[TLSCABundleKey])
		Expect(err).ToNot(HaveOccurred())
		Expect(caBundleCerts).To(HaveLen(2))
	})
})
