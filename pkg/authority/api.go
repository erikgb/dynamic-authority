package authority

import (
	"crypto/tls"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	admissionregistrationv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DynamicAuthoritySecretLabel will - if set to "true" - make the dynamic
	// authority CA controller inject and maintain a dynamic CA.
	// The label must be added to Secret resource that want to denote that they
	// can be directly injected into injectables that have a
	// `inject-dynamic-ca-from-secret` label.
	// If an injectable references a Secret that does NOT have this annotation,
	// the dynamic ca-injector will refuse to inject the secret.
	DynamicAuthoritySecretLabel = "cert-manager.io/allow-dynamic-ca-injection"
	// WantInjectFromSecretNamespaceLabel is the label that specifies that a
	// particular object wants injection of dynamic CAs from secret in
	// namespace.
	// Must be used in conjunction with WantInjectFromSecretNameLabel.
	WantInjectFromSecretNamespaceLabel = "cert-manager.io/inject-dynamic-ca-from-secret-namespace"
	// WantInjectFromSecretNameLabel is the label that specifies that a
	// particular object wants injection of dynamic CAs from secret with name.
	// Must be used in conjunction with WantInjectFromSecretNamespaceLabel.
	WantInjectFromSecretNameLabel = "cert-manager.io/inject-dynamic-ca-from-secret-name"

	// TLSCABundleKey is used as a data key in Secret resources to store a CA
	// certificate bundle.
	TLSCABundleKey = "ca-bundle.crt"

	// RenewCertificateSecretAnnotation is an annotation that can be set to
	// an arbitrary value on a certificate secret to trigger a renewal of the
	// certificate managed in the secret.
	RenewCertificateSecretAnnotation = "renew.cert-manager.io/requestedAt"
	// RenewHandledCertificateSecretAnnotation is an annotation that will be set on a
	// certificate secret whenever a new certificate is renewed using the
	// RenewCertificateSecretAnnotation annotation.
	RenewHandledCertificateSecretAnnotation = "renew.cert-manager.io/lastRequestedAt"
)

type ApplyConfiguration interface {
	GetName() *string
}

type Injectable interface {
	GroupVersionKind() schema.GroupVersionKind
	InjectCA(obj *unstructured.Unstructured, caBundle []byte) (ApplyConfiguration, error)
}

type ValidatingWebhookCaBundleInject struct {
}

func (i *ValidatingWebhookCaBundleInject) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "admissionregistration.k8s.io",
		Version: "v1",
		Kind:    "ValidatingWebhookConfiguration",
	}
}

func (i *ValidatingWebhookCaBundleInject) InjectCA(obj *unstructured.Unstructured, caBundle []byte) (ApplyConfiguration, error) {
	// TODO: Can we generalize this function for any resource based on a JSON path?

	ac := admissionregistrationv1ac.ValidatingWebhookConfiguration(obj.GetName())

	webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
	if err != nil {
		return nil, err
	}
	for _, w := range webhooks {
		name, _, err := unstructured.NestedString(w.(map[string]any), "name")
		if err != nil {
			return nil, err
		}
		ac.WithWebhooks(
			admissionregistrationv1ac.ValidatingWebhook().
				WithName(name).
				WithClientConfig(admissionregistrationv1ac.WebhookClientConfig().
					WithCABundle(caBundle...),
				),
		)
	}

	return ac, nil
}

var _ Injectable = &ValidatingWebhookCaBundleInject{}

type Options struct {
	// The namespace used for certificate secrets.
	Namespace string

	// The name of the Secret used to store CA certificates.
	CASecret string

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than LeafDuration.
	CADuration time.Duration

	DNSNames []string

	// The amount of time leaf certificates signed by this authority will be
	// valid for.
	// This must be less than CADuration.
	LeafDuration time.Duration

	Injectables []Injectable
}

type ServingCertificateOperator struct {
	Options Options

	certificateHolder *CertificateHolder
}

func (o *ServingCertificateOperator) ServingCertificate() func(config *tls.Config) {
	if o.certificateHolder == nil {
		o.certificateHolder = &CertificateHolder{}
	}
	return func(config *tls.Config) {
		config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return o.certificateHolder.GetCertificate(info)
		}
	}
}

// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;patch

func (o *ServingCertificateOperator) SetupWithManager(mgr ctrl.Manager) error {
	if o.certificateHolder == nil {
		return errors.New("ServingCertificate not invoked")
	}

	if o.Options.CADuration == 0 {
		o.Options.CADuration = 7 * 24 * time.Hour
	}
	if o.Options.LeafDuration == 0 {
		o.Options.LeafDuration = 1 * 24 * time.Hour
	}
	if len(o.Options.Injectables) == 0 {
		o.Options.Injectables = []Injectable{
			&ValidatingWebhookCaBundleInject{},
		}
	}

	cacheByObject := map[client.Object]cache.ByObject{
		&corev1.Secret{}: {
			Namespaces: map[string]cache.Config{
				o.Options.Namespace: {},
			},
			Label: labels.SelectorFromSet(labels.Set{
				DynamicAuthoritySecretLabel: "true",
			}),
		},
	}
	injectByObject := cache.ByObject{
		Label: labels.SelectorFromSet(labels.Set{
			WantInjectFromSecretNamespaceLabel: o.Options.Namespace,
			WantInjectFromSecretNameLabel:      o.Options.CASecret,
		}),
	}
	for _, injectable := range o.Options.Injectables {
		cacheByObject[newUnstructured(injectable)] = injectByObject
	}
	controllerCache, err := cache.New(mgr.GetConfig(), cache.Options{
		HTTPClient:                  mgr.GetHTTPClient(),
		Scheme:                      mgr.GetScheme(),
		Mapper:                      mgr.GetRESTMapper(),
		ReaderFailOnMissingInformer: true,
		ByObject:                    cacheByObject,
	})
	if err := mgr.Add(controllerCache); err != nil {
		return err
	}

	controllerClient, err := client.New(mgr.GetConfig(), client.Options{
		HTTPClient: mgr.GetHTTPClient(),
		Scheme:     mgr.GetScheme(),
		Mapper:     mgr.GetRESTMapper(),
		Cache: &client.CacheOptions{
			Reader:       controllerCache,
			Unstructured: true,
		},
	})
	if err != nil {
		return err
	}

	r := reconciler{
		Client: controllerClient,
		Cache:  controllerCache,
		Opts:   o.Options,
	}
	controllers := []dynamicAuthorityController{
		&CASecretReconciler{reconciler: r},
		&LeafCertReconciler{reconciler: r, certificateHolder: o.certificateHolder},
	}
	for _, injectable := range o.Options.Injectables {
		controllers = append(controllers, &InjectableReconciler{reconciler: r, Injectable: injectable})
	}
	for _, c := range controllers {
		if err := c.SetupWithManager(mgr); err != nil {
			return err
		}
	}

	return nil
}

type dynamicAuthorityController interface {
	SetupWithManager(ctrl.Manager) error
}

func newUnstructured(injectable Injectable) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(injectable.GroupVersionKind())
	return obj
}

func newUnstructuredList(injectable Injectable) *unstructured.UnstructuredList {
	obj := &unstructured.UnstructuredList{}
	obj.SetGroupVersionKind(injectable.GroupVersionKind())
	return obj
}
