package validate

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
)

var host = capabilities.NewHost()

var (
	namespaceObjectData map[string]interface{}
	namespaceObjectType = types.NewObjectType("namespaceObject")
)

// namespaceObject provides an implementation of ref.Val for
// any object type that has receiver functions but does not expose any fields to
// CEL.
type namespaceObject struct {
	namespace string
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (a namespaceObject) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, fmt.Errorf("type conversion error from '%s' to '%v'", namespaceObjectType.String(), typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (a namespaceObject) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case namespaceObjectType:
		return a
	case types.TypeType:
		return namespaceObjectType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", namespaceObjectType, typeVal)
}

// Equal implements ref.Val.Equal.
func (a namespaceObject) Equal(_ ref.Val) ref.Val {
	return types.NoSuchOverloadErr()
}

// Type implements ref.Val.Type.
func (a namespaceObject) Type() ref.Type {
	return namespaceObjectType
}

// Value implements ref.Val.Value.
func (a namespaceObject) Value() any {
	return namespaceObjectData
}

// Get returns the value fo a field name.
func (a namespaceObject) Get(field ref.Val) ref.Val {
	if namespaceObjectData == nil {
		resourceRequest := kubernetes.GetResourceRequest{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       a.namespace,
		}

		responseBytes, err := kubernetes.GetResource(&host, resourceRequest)
		if err != nil {
			return types.NewErr("cannot get namespace data: %s. `namespaceObject` cannot be populated.", err)
		}

		err = json.Unmarshal(responseBytes, &namespaceObjectData)
		if err != nil {
			return types.NewErr("cannot parse namespace data: %w", err)
		}
	}

	fieldName, ok := field.Value().(string)
	if !ok {
		return types.ValOrErr(field, "no such field")
	}

	value, found := namespaceObjectData[fieldName]
	if !found {
		return types.ValOrErr(field, "no such field")
	}

	return types.DefaultTypeAdapter.NativeToValue(value)
}
