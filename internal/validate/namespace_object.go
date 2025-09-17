package validate

import (
	"encoding/json"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
)

var (
	host                = capabilities.NewHost()
	namespaceObjectData map[string]interface{}
)

func getNamespaceObject(name string) ref.Val {
	if namespaceObjectData == nil {
		resourceRequest := kubernetes.GetResourceRequest{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       name,
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

	return types.NewDynamicMap(types.DefaultTypeAdapter, namespaceObjectData)
}

func getKubernetesResource(name string, namespace string, apiVersion string, kind string) ref.Val {
	resourceRequest := kubernetes.GetResourceRequest{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		Namespace:  &namespace,
	}

	responseBytes, err := kubernetes.GetResource(&host, resourceRequest)
	if err != nil {
		return types.NewErr("cannot get Kubernetes resource: %s", err)
	}

	var response map[string]any
	if err = json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes resource response: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}

func getKubernetesResourceList(namespace string, apiVersion string, kind string) ref.Val {
	resourceRequest := kubernetes.ListResourcesByNamespaceRequest{
		APIVersion: apiVersion,
		Kind:       kind,
		Namespace:  namespace,
	}

	responseBytes, err := kubernetes.ListResourcesByNamespace(&host, resourceRequest)
	if err != nil {
		return types.NewErr("cannot list Kubernetes resources: %s", err)
	}

	var response []any
	if err = json.Unmarshal(responseBytes, &response); err != nil {
		return types.NewErr("cannot unmarshal Kubernetes resource response: %s", err)
	}

	return types.NewDynamicList(types.DefaultTypeAdapter, response)
}
