package authority

import (
	"crypto/tls"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/erikgb/dynamic-authority/internal/pki"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var _ = Describe("Leaf Certificate Controller", Ordered, func() {
	var (
		caSecret    *corev1.Secret
		caSecretRef types.NamespacedName
		certHolder  *CertificateHolder
	)

	BeforeAll(func() {
		opts := Options{
			Namespace:  "leaf-cert-controller",
			CASecret:   "ca-cert",
			CADuration: 7 * 24 * time.Hour,
		}

		ns := &corev1.Namespace{}
		ns.Name = opts.Namespace
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caCert, caPK, err := generateCA(opts)
		Expect(err).ToNot(HaveOccurred())
		caCertBytes, err := pki.EncodeX509(caCert)
		Expect(err).ToNot(HaveOccurred())
		pkBytes, err := pki.EncodePrivateKey(caPK)
		Expect(err).ToNot(HaveOccurred())

		caSecret = &corev1.Secret{}
		caSecret.Namespace = opts.Namespace
		caSecret.Name = opts.CASecret
		caSecret.Type = corev1.SecretTypeTLS
		caSecret.Labels = map[string]string{
			DynamicAuthoritySecretLabel: "true",
		}
		caSecret.Data = map[string][]byte{
			corev1.TLSCertKey:       caCertBytes,
			corev1.TLSPrivateKeyKey: pkBytes,
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

		certHolder = &CertificateHolder{}
		controller := &LeafCertReconciler{
			reconciler: reconciler{
				Client: k8sManager.GetClient(),
				Cache:  k8sManager.GetCache(),
				Opts:   opts,
			},
			certificateHolder: certHolder,
		}
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

	It("should set certificate", func() {
		Eventually(func() (*tls.Certificate, error) {
			return certHolder.GetCertificate(nil)
		}).ShouldNot(BeNil())
	})
})
