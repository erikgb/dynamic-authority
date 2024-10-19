package controller

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime"
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
	return (&CASecretReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Opts:   opts,
	}).SetupWithManager(mgr)
}
