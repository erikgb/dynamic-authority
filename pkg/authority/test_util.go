package authority

import (
	"errors"
	"fmt"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	"github.com/erikgb/dynamic-authority/internal/pki"
)

func assertCASecret(secret *corev1.Secret) {
	Eventually(komega.Object(secret)).Should(And(
		HaveField("Labels", HaveKeyWithValue(DynamicAuthoritySecretLabel, "true")),
		HaveField("Type", Equal(corev1.SecretTypeTLS)),
		HaveField("Data", And(
			HaveKeyWithValue(corev1.TLSCertKey, Not(BeEmpty())),
			HaveKeyWithValue(corev1.TLSPrivateKeyKey, Not(BeEmpty())),
			HaveKeyWithValue(TLSCABundleKey, Not(BeEmpty())),
		)),
	))

	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	Expect(err).ToNot(HaveOccurred())
	caBundle, err := pki.DecodeX509CertificateSetBytes(secret.Data[TLSCABundleKey])
	Expect(err).ToNot(HaveOccurred())

	Expect(secretPublicKeysDiffer(secret)).To(BeFalse())
	Expect(cert.Subject).To(Equal(cert.Issuer))
	Expect(caBundle).To(ContainElement(cert))
}

func NewValidatingWebhookConfigurationForTest(name string, caSecret types.NamespacedName) *admissionregistrationv1.ValidatingWebhookConfiguration {
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	vwc.Name = name
	vwc.Labels = map[string]string{
		WantInjectFromSecretNamespaceLabel: caSecret.Namespace,
		WantInjectFromSecretNameLabel:      caSecret.Name,
	}
	vwc.Webhooks = []admissionregistrationv1.ValidatingWebhook{
		newValidatingWebhookForTest("foo-webhook.cert-manager.io"),
		newValidatingWebhookForTest("bar-webhook.cert-manager.io"),
	}
	return vwc
}

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

func secretPublicKeysDiffer(secret *corev1.Secret) (bool, error) {
	pk, err := pki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return true, fmt.Errorf("secret contains invalid private key data: %w", err)
	}
	x509Cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return true, fmt.Errorf("secret contains an invalid certificate: %w", err)
	}

	equal, err := pki.PublicKeysEqual(x509Cert.PublicKey, pk.Public())
	if err != nil {
		return true, fmt.Errorf("secret contains an invalid key-pair: %w", err)
	}
	if !equal {
		return true, errors.New("secret contains a private key that does not match the certificate")
	}

	return false, nil
}
