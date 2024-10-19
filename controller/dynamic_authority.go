package controller

import ctrl "sigs.k8s.io/controller-runtime"

func SetupWithManager(mgr ctrl.Manager) error {
	return (&CASecretReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr)
}
