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

// Kubernetes returns a cel.EnvOption to configure CEL-namespaced Kubernetes
// host-callback Kubewarden functions.
//
// # Kubernetes.ListResourcesByNamespace
//
// This CEL function returns all the Kubernetes resources in a specific Kubernetes namespace,
// filtered via the options in ListResourcesByNamespaceRequest{}. See the Go
// SDK for more information on ListResourcesByNamespaceRequest{}.
// Usage in CEL:
//
// k8s.listResourcesByNamespace(ListResourcesByNamespaceRequest{Namespace: <string>}) ->
//
//	map(key, value) where:
//	  key is a <string> "items"
//	  value is a <list<object>> matching GroupVersionKind from "github.com/kubewarden/k8s-objects"
//
// Example:
//
//	 kw.k8s.listResourcesByNamespace(ListResourcesByNamespaceRequest{Namespace: 'default'}).items[0]
//	 returns:
//	{
//	  Kind: "Pod",
//	  Metadata: {
//	    Name:      "nginx",
//	    Namespace: "default",
//	  },
//	}
//
// # Kubernetes.ListAllResources
//
// This CEL function returns all the Kubernetes resources,
// filtered via the options in ListAllResourcesRequest{}. See the Go
// SDK for more information on ListAllResourcesRequest{}.
// Usage in CEL:
//
//	k8s.listAllResources(ListAllResourcesRequest{Kind: <string>}) ->
//	  map(key, value) where:
//	  key is a <string> "items"
//	  value is a <list<object>> matching GroupVersionKind from "github.com/kubewarden/k8s-objects"
//
// Example:
//
//	kw.k8s.listAllResources(listAllResourcesRequest{Kind: 'Pod'}).items[0]
//	 returns:
//	{
//	  Kind: "Pod",
//	  Metadata: {
//	    Name:      "nginx",
//	    Namespace: "default",
//	  },
//	}
//
// # Kubernetes.getResource
//
// This CEL function returns a specific Kubernetes resources,
// selected via the options in getResourceRequest{}. See the Go
// SDK for more information on getResourceRequest{}.
// Usage in CEL:
//
//	k8s.getResource(getResourceRequest{Kind: <string>}) ->
//	  <object> matching GroupVersionKind from "github.com/kubewarden/k8s-objects"
//
// Example:
//
// kw.k8s.getResource(getResourceRequest{Kind: 'Pod'})
// returns:
//
//	{
//	  Kind: "Pod",
//	  Metadata: {
//	    Name:      "nginx",
//	    Namespace: "default",
//	  },
//	}
func Kubernetes() cel.EnvOption {
	return cel.Lib(kubernetesLib{})
}

type kubernetesLib struct{}

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
