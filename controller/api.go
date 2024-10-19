package controller

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime"
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
	DynamicAuthoritySecretLabel = "cert-manager.io/inject-dynamic-ca"
	// WantInjectFromSecretLabel is the label that specifies that a particular
	// object wants injection of dynamic CAs.  It takes the form of a reference to
	// a Secret as name.
	WantInjectFromSecretLabel = "cert-manager.io/inject-dynamic-ca-from-secret"

	// TLSCABundleKey is used as a data key in Secret resources to store a CA certificate bundle.
	TLSCABundleKey = "ca-bundle.crt"
)

type Options struct {
	CASecret types.NamespacedName
}

func SetupWithManager(mgr controllerruntime.Manager, opts Options) error {
	namespacedCache, err := cache.New(mgr.GetConfig(), cache.Options{
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
		},
	})
	if err := mgr.Add(namespacedCache); err != nil {
		return err
	}

	namespacedClient, err := client.New(mgr.GetConfig(), client.Options{
		HTTPClient: mgr.GetHTTPClient(),
		Scheme:     mgr.GetScheme(),
		Mapper:     mgr.GetRESTMapper(),
		Cache: &client.CacheOptions{
			Reader: namespacedCache,
		},
	})
	if err != nil {
		return err
	}

	return (&CASecretReconciler{
		Client: namespacedClient,
		Cache:  namespacedCache,
		Opts:   opts,
	}).SetupWithManager(mgr)
}
