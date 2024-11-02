package authority

import (
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	fieldOwner = client.FieldOwner("cert-manager-dynamic-authority")
)

func newApplyPatch(ac ApplyConfiguration) applyPatch {
	return applyPatch{ac: ac}
}

type applyPatch struct {
	ac ApplyConfiguration
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return json.Marshal(p.ac)
}
