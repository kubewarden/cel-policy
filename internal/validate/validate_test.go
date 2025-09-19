package validate

import (
	"encoding/json"
	"testing"

	"github.com/kubewarden/cel-policy/internal/settings"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	kubewardenProtocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/admissionregistration"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name                       string
		settings                   settings.Settings
		object                     interface{}
		expectedValidationResponse kubewardenProtocol.ValidationResponse
	}{
		{
			name: "test validation with message",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: "object.metadata.name != 'pod-name'",
						Message:    "not true",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "pod-name",
					Namespace: "default",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("not true"),
				Code:     code(400),
			},
		},
		{
			name: "test validation with message expression",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression:        "object.metadata.name != 'namespace-name'",
						MessageExpression: "object.metadata.name + ' is not allowed'",
					},
				},
			},
			object: &corev1.Namespace{
				Metadata: &metav1.ObjectMeta{
					Name: "namespace-name",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("namespace-name is not allowed"),
				Code:     code(400),
			},
		},
		{
			name: "test validation without message",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: "object.metadata.name != 'pod-name'",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "pod-name",
					Namespace: "default",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("failed expression: object.metadata.name != 'pod-name'"),
				Code:     code(400),
			},
		},
		{
			name: "test validation user defined reason message",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: "object.metadata.name != 'pod-name'",
						Reason:     settings.StatusReasonUnauthorized,
						Message:    "failed",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "pod-name",
					Namespace: "default",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("failed"),
				Code:     code(401),
			},
		},
		{
			name: "test validation user defined reason message",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: "object.metadata.name != 'pod-name'",
						Message:    "failed",
						Reason:     settings.StatusReasonUnauthorized,
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "pod-name",
					Namespace: "default",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("failed"),
				Code:     code(401),
			},
		},
		{
			name: "test validation with variables",
			settings: settings.Settings{
				Variables: []settings.Variable{
					{
						Name:       "forbiddenName",
						Expression: "'pod-name'",
					},
					{
						Name:       "podMeta",
						Expression: "request.object.metadata",
					},
					{
						Name:       "podName",
						Expression: "variables.podMeta.name",
					},
				},
				Validations: []settings.Validation{
					{
						Expression:        "variables.podName != variables.forbiddenName",
						MessageExpression: "variables.forbiddenName + ' is forbidden'",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "pod-name",
					Namespace: "default",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("pod-name is forbidden"),
				Code:     code(400),
			},
		},
		{
			name: "namespaceObject lazy loading",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: "namespaceObject.metadata.labels.foo == 'bar'",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      "pod-name",
					Namespace: "default",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: true,
			},
		},
	}

	// Override the host capabilities client with a mock client
	request, err := json.Marshal(&kubernetes.GetResourceRequest{
		APIVersion: "v1",
		Kind:       "Namespace",
		Name:       "default",
	})
	require.NoError(t, err)

	response, err := json.Marshal(&corev1.Namespace{
		Metadata: &metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
	})
	require.NoError(t, err)

	mockWapcClient := &mocks.MockWapcClient{}
	mockWapcClient.On("HostCall", "kubewarden", "kubernetes", "get_resource", request).Return(response, nil)

	host.Client = mockWapcClient

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings, err := json.Marshal(test.settings)
			require.NoError(t, err)

			object, err := json.Marshal(test.object)
			require.NoError(t, err)

			validationRequest := kubewardenProtocol.ValidationRequest{
				Request: kubewardenProtocol.KubernetesAdmissionRequest{
					Namespace: "default",
					Object:    object,
				},
				Settings: settings,
			}
			payload, err := json.Marshal(validationRequest)
			require.NoError(t, err)

			response, err = Validate(payload)
			require.NoError(t, err)

			validationResponse := kubewardenProtocol.ValidationResponse{}
			err = json.Unmarshal(response, &validationResponse)
			require.NoError(t, err)

			assert.Equal(t, test.expectedValidationResponse, validationResponse)
		})
	}
}

func TestLabelSelectorParsing(t *testing.T) {
	labelSelector := k8smetav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": "my-app",
		},
		MatchExpressions: []k8smetav1.LabelSelectorRequirement{
			{
				Key:      "environment",
				Operator: k8smetav1.LabelSelectorOpIn,
				Values:   []string{"production", "staging"},
			},
			{
				Key:      "phase",
				Operator: k8smetav1.LabelSelectorOpNotIn,
				Values:   []string{"initial", "final"},
			},
			{
				Key:      "foo",
				Operator: k8smetav1.LabelSelectorOpExists,
				Values:   []string{},
			},
			{
				Key:      "bar",
				Operator: k8smetav1.LabelSelectorOpDoesNotExist,
				Values:   []string{},
			},
		},
	}

	labelSelectorString, err := formatLabelSelectorString(&labelSelector)
	require.NoError(t, err)
	require.Equal(t, "app=my-app,!bar,environment in (production,staging),foo,phase notin (final,initial)", labelSelectorString)
}

func TestPerNamespaceParameter(t *testing.T) {
	tests := []struct {
		name       string
		settings   settings.Settings
		requestMap map[string]any
		namespace  string
		apiVersion string
		kind       string
	}{
		{
			name: "paramref with no namspace should use request namespace",
			settings: settings.Settings{
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ParamRef: &admissionregistration.ParamRef{
					Namespace: "",
				},
			},
			requestMap: map[string]any{
				"namespace": "default",
			},
			namespace:  "default",
			apiVersion: "v1",
			kind:       "ConfigMap",
		},
		{
			name: "paramref with namspace should use it instead of request namespace",
			settings: settings.Settings{
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ParamRef: &admissionregistration.ParamRef{
					Namespace: "config",
				},
			},
			requestMap: map[string]any{
				"namespace": "default",
			},
			namespace:  "config",
			apiVersion: "v1",
			kind:       "ConfigMap",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validationRequest := ValidationRequest{
				Settings: test.settings,
			}
			namespace, apiVersion, kind := getResourceInfo(validationRequest, test.requestMap)
			require.Equal(t, test.namespace, namespace)
			require.Equal(t, test.apiVersion, apiVersion)
			require.Equal(t, test.kind, kind)
		})
	}
}

// message is a helper function to create a pointer to a string.
func message(s string) *string {
	return &s
}

// code is a helper function to create a pointer to a uint16.
func code(i uint16) *uint16 {
	return &i
}
