package controller

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
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
	// WantInjectFromSecretNamespaceLabel is the label that specifies that a particular
	// object wants injection of dynamic CAs from secret in namespace.
	// Must be used in conjunction with WantInjectFromSecretNameLabel.
	WantInjectFromSecretNamespaceLabel = "cert-manager.io/inject-dynamic-ca-from-secret-namespace"
	// WantInjectFromSecretNameLabel is the label that specifies that a particular
	// object wants injection of dynamic CAs from secret with name.
	// Must be used in conjunction with WantInjectFromSecretNamespaceLabel.
	WantInjectFromSecretNameLabel = "cert-manager.io/inject-dynamic-ca-from-secret-name"

	// TLSCABundleKey is used as a data key in Secret resources to store a CA certificate bundle.
	TLSCABundleKey = "ca-bundle.crt"
)

type Options struct {
	CASecret types.NamespacedName
}

type DynamicAuthorityController interface {
	SetupWithManager(ctrl.Manager) error
}

func SetupWithManager(mgr controllerruntime.Manager, opts Options) error {
	var injectableRequirements []labels.Requirement
	for _, k := range []string{WantInjectFromSecretNamespaceLabel, WantInjectFromSecretNameLabel} {
		r, err := labels.NewRequirement(k, selection.Exists, nil)
		if err != nil {
			return err
		}
		injectableRequirements = append(injectableRequirements, *r)
	}

	controllerCache, err := cache.New(mgr.GetConfig(), cache.Options{
		HTTPClient:                  mgr.GetHTTPClient(),
		Scheme:                      mgr.GetScheme(),
		Mapper:                      mgr.GetRESTMapper(),
		ReaderFailOnMissingInformer: true,
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Namespaces: map[string]cache.Config{
					opts.CASecret.Namespace: {},
				},
				Label: labels.SelectorFromSet(labels.Set{DynamicAuthoritySecretLabel: "true"}),
			},
			&admissionregistrationv1.ValidatingWebhookConfiguration{}: {
				Label: labels.NewSelector().Add(injectableRequirements...),
			},
		},
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

	controllers := []DynamicAuthorityController{
		&CASecretReconciler{
			Client: controllerClient,
			Cache:  controllerCache,
			Opts:   opts,
		},
		&InjectableReconciler{
			Client: controllerClient,
			Cache:  controllerCache,
			Opts:   opts,
		},
	}
	for _, c := range controllers {
		if err := c.SetupWithManager(mgr); err != nil {
			return err
		}
	}

	return nil
}
