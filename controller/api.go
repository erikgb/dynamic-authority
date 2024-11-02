package controller

import (
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	admissionregistrationv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime"
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

	// IssuedCertificateSecretAnnotation is an annotation that will be set on a
	// certificate secret whenever a new certificate is issued.
	// The value must be a timestamp in the RFC 3339 format.
	IssuedCertificateSecretAnnotation = "renew.cert-manager.io/issuedAt"
	// RenewCertificateSecretAnnotation is an annotation that can be set on a
	// certificate secret to trigger a renewal of the certificate managed in
	// the secret.
	// The value must be a timestamp in the RFC 3339 format, and must be after
	// IssuedCertificateSecretAnnotation to trigger the renewal.
	RenewCertificateSecretAnnotation = "renew.cert-manager.io/requestedAt"
)

type ApplyConfiguration interface {
	GetName() *string
}

type Injectable interface {
	GroupVersionKind() schema.GroupVersionKind
	GetObject() client.Object
	GetObjectList() client.ObjectList
	InjectCA(obj client.Object, caBytes []byte) ApplyConfiguration
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

func (i *ValidatingWebhookCaBundleInject) GetObject() client.Object {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{}
}

func (i *ValidatingWebhookCaBundleInject) GetObjectList() client.ObjectList {
	return &admissionregistrationv1.ValidatingWebhookConfigurationList{}
}

func (i *ValidatingWebhookCaBundleInject) InjectCA(obj client.Object, caBundle []byte) ApplyConfiguration {
	vwc := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration)

	clientConfig := admissionregistrationv1ac.WebhookClientConfig().
		WithCABundle(caBundle...)

	ac := admissionregistrationv1ac.ValidatingWebhookConfiguration(vwc.Name)
	for _, w := range vwc.Webhooks {
		ac.WithWebhooks(
			admissionregistrationv1ac.ValidatingWebhook().
				WithName(w.Name).
				WithClientConfig(clientConfig),
		)
	}

	return ac
}

var _ Injectable = &ValidatingWebhookCaBundleInject{}

type Options struct {
	// The namespace used for certificate secrets.
	Namespace string

	// The name of the Secret used to store CA certificates.
	CASecret string

	// The name of the Secret used to store leaf certificates.
	LeafSecret string

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than LeafDuration.
	CADuration time.Duration

	// The amount of time leaf certificates signed by this authority will be
	// valid for.
	// This must be less than CADuration.
	LeafDuration time.Duration

	Injectables []Injectable
}

// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;patch

func SetupWithManager(mgr controllerruntime.Manager, opts Options) error {
	cacheByObject := map[client.Object]cache.ByObject{
		&corev1.Secret{}: {
			Namespaces: map[string]cache.Config{
				opts.Namespace: {},
			},
			Label: labels.SelectorFromSet(labels.Set{
				DynamicAuthoritySecretLabel: "true",
			}),
		},
	}
	injectByObject := cache.ByObject{
		Label: labels.SelectorFromSet(labels.Set{
			WantInjectFromSecretNamespaceLabel: opts.Namespace,
			WantInjectFromSecretNameLabel:      opts.CASecret,
		}),
	}
	for _, injectable := range opts.Injectables {
		cacheByObject[injectable.GetObject()] = injectByObject
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
			Reader: controllerCache,
		},
	})
	if err != nil {
		return err
	}

	r := reconciler{
		Client: controllerClient,
		Cache:  controllerCache,
		Opts:   opts,
	}
	controllers := []dynamicAuthorityController{
		&CASecretReconciler{reconciler: r},
	}
	for _, injectable := range opts.Injectables {
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
