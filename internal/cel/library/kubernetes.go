package library

import (
	"encoding/json"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
)

type kubernetesLib struct{}

func Kubernetes() cel.EnvOption {
	return cel.Lib(kubernetesLib{})
}

// LibraryName implements the SingletonLibrary interface method.
func (kubernetesLib) LibraryName() string {
	return "kw.k8s"
}

// CompileOptions implements the Library interface method.
func (kubernetesLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Container("kubernetes"),

		ext.NativeTypes(reflect.TypeOf(&kubernetes.ListResourcesByNamespaceRequest{})),
		ext.NativeTypes(reflect.TypeOf(&kubernetes.ListAllResourcesRequest{})),
		ext.NativeTypes(reflect.TypeOf(&kubernetes.GetResourceRequest{})),

		cel.Function("kw.k8s.listResourcesByNamespace",
			cel.Overload("kw_k8s_list_resources_by_namespace_request",
				[]*cel.Type{cel.ObjectType("kubernetes.ListResourcesByNamespaceRequest")},
				cel.DynType,
				cel.UnaryBinding(listResourcesByNamespace),
			),
		),
		cel.Function("kw.k8s.listAllResources",
			cel.Overload("kw_k8s_list_all_resources_request",
				[]*cel.Type{cel.ObjectType("kubernetes.ListAllResourcesRequest")},
				cel.DynType,
				cel.UnaryBinding(listAllResources),
			),
		),
		cel.Function("kw.k8s.getResource",
			cel.Overload("kw_k8s_get_resource_request",
				[]*cel.Type{cel.ObjectType("kubernetes.GetResourceRequest")},
				cel.DynType,
				cel.UnaryBinding(getResource),
			),
		),
	}
}

// ProgramOptions implements the Library interface method.
func (kubernetesLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func listAllResources(arg ref.Val) ref.Val {
	listAllResourcesRequest, ok := arg.Value().(*kubernetes.ListAllResourcesRequest)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	responseBytes, err := kubernetes.ListResources(&host, *listAllResourcesRequest)
	if err != nil {
		return types.NewErr("cannot list all Kubernetes resources: %s", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes all resources response: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}

func listResourcesByNamespace(arg ref.Val) ref.Val {
	listResourcesByNamespaceRequest, ok := arg.Value().(*kubernetes.ListResourcesByNamespaceRequest)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	responseBytes, err := kubernetes.ListResourcesByNamespace(&host, *listResourcesByNamespaceRequest)
	if err != nil {
		return types.NewErr("cannot list Kubernetes resources by namespace: %s", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes resources by namespace response: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}

func getResource(arg ref.Val) ref.Val {
	getResourceRequest, ok := arg.Value().(*kubernetes.GetResourceRequest)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	var response map[string]interface{}
	responseBytes, err := kubernetes.GetResource(&host, *getResourceRequest)
	if err != nil {
		return types.NewErr("cannot get Kubernetes resource: %s", err)
	}
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes resource response: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}
