package controller

import (
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	fieldOwner = client.FieldOwner("cert-manager-dynamic-authority")
)

var byLabelFilter = func(key, value string) func(object client.Object) bool {
	return func(object client.Object) bool {
		return object.GetLabels()[key] == value
	}
}

type applyConfiguration interface {
	GetName() *string
}

func newApplyPatch(ac applyConfiguration) applyPatch {
	return applyPatch{ac: ac}
}

type applyPatch struct {
	ac applyConfiguration
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return json.Marshal(p.ac)
}

type errorIs func(err error) bool

func ignoreErr(err error, is ...errorIs) error {
	for _, f := range is {
		if f(err) {
			return nil
		}
	}
	return err
}
