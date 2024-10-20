package controller

import (
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	// The namespaced name of the Secret used to store CA certificates.
	CASecret types.NamespacedName

	// The namespaced name of the Secret used to leaf certificates.
	LeafSecret types.NamespacedName

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than LeafDuration.
	CADuration time.Duration

	// The amount of time leaf certificates signed by this authority will be
	// valid for.
	// This must be less than CADuration.
	LeafDuration time.Duration
}

type DynamicAuthorityController interface {
	SetupWithManager(ctrl.Manager) error
}

func SetupWithManager(mgr controllerruntime.Manager, opts Options) error {
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
				Label: labels.SelectorFromSet(labels.Set{
					DynamicAuthoritySecretLabel: "true",
				}),
			},
			&admissionregistrationv1.ValidatingWebhookConfiguration{}: {
				Label: labels.SelectorFromSet(labels.Set{
					WantInjectFromSecretNamespaceLabel: opts.CASecret.Namespace,
					WantInjectFromSecretNameLabel:      opts.CASecret.Name,
				}),
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

	reconciler := reconciler{
		Client: controllerClient,
		Cache:  controllerCache,
		Opts:   opts,
	}
	controllers := []DynamicAuthorityController{
		&CASecretReconciler{reconciler: reconciler},
		&InjectableReconciler{reconciler: reconciler},
	}
	for _, c := range controllers {
		if err := c.SetupWithManager(mgr); err != nil {
			return err
		}
	}

	return nil
}
