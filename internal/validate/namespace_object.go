package validate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	selection "k8s.io/apimachinery/pkg/selection"
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

// This function is used by the policy to get the params using selector
func getKubernetesResourceList(namespace string, apiVersion string, kind string, selector *metav1.LabelSelector) ([]any, error) {
	labelSelectorString, err := formatLabelSelectorString(selector)
	if err != nil {
		return nil, err
	}
	resourceRequest := kubernetes.ListResourcesByNamespaceRequest{
		APIVersion:    apiVersion,
		Kind:          kind,
		Namespace:     namespace,
		LabelSelector: &labelSelectorString,
	}

	responseBytes, err := kubernetes.ListResourcesByNamespace(&host, resourceRequest)
	if err != nil {
		return nil, fmt.Errorf("cannot list Kubernetes resources: %s", err)
	}

	var response map[string]any
	if err = json.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("cannot unmarshal Kubernetes list resources response: %s", err)
	}
	items, ok := response["items"].([]any)
	if !ok {
		return nil, fmt.Errorf("cannot unmarshal Kubernetes list resources response: %s", err)
	}
	return items, nil
}

// Function used to format a metav1.LabelSelector into a string that can be understood
// by Kubewarden host capabilities.
func formatLabelSelectorString(selector *metav1.LabelSelector) (string, error) {
	if selector == nil {
		return "", errors.New("paramRef.selector is nil")
	}
	labelSelectorBuilder := labels.NewSelector()
	for key, value := range selector.MatchLabels {
		requirement, err := labels.NewRequirement(key, selection.Equals, []string{value})
		if err != nil {
			return "", err
		}
		labelSelectorBuilder = labelSelectorBuilder.Add(*requirement)
	}
	for _, matchExpression := range selector.MatchExpressions {
		operator, err := getOperationString(matchExpression.Operator)
		if err != nil {
			return "", err
		}
		requirement, err := labels.NewRequirement(matchExpression.Key, operator, matchExpression.Values)
		if err != nil {
			return "", err
		}
		labelSelectorBuilder = labelSelectorBuilder.Add(*requirement)
	}

	return labelSelectorBuilder.String(), nil
}

func getOperationString(op metav1.LabelSelectorOperator) (selection.Operator, error) {
	if op == metav1.LabelSelectorOpIn {
		return selection.In, nil
	}
	if op == metav1.LabelSelectorOpNotIn {
		return selection.NotIn, nil
	}
	if op == metav1.LabelSelectorOpExists {
		return selection.Exists, nil
	}
	if op == metav1.LabelSelectorOpDoesNotExist {
		return selection.DoesNotExist, nil
	}
	return "", errors.New("unknown label selector operator")
}
