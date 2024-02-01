package validate

import (
	"encoding/json"
	"testing"

	"github.com/kubewarden/cel-policy/internal/settings"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	kubewardenProtocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
						Expression: `object.metadata.name != "pod-name"`,
						Message:    "not true",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "pod-name",
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
						Expression:        `object.metadata.name != "pod-name"`,
						MessageExpression: `object.metadata.name + " is not true"`,
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "pod-name",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("pod-name is not true"),
				Code:     code(400),
			},
		},
		{
			name: "test validation without message",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: `object.metadata.name != "pod-name"`,
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "pod-name",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message(`failed expression: object.metadata.name != "pod-name"`),
				Code:     code(400),
			},
		},
		{
			name: "test validation user defined reason message",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: `object.metadata.name != "pod-name"`,
						Reason:     settings.StatusReasonUnauthorized,
						Message:    "failed",
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "pod-name",
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
						Expression: `object.metadata.name != "pod-name"`,
						Message:    "failed",
						Reason:     settings.StatusReasonUnauthorized,
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "pod-name",
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
						Expression: `"pod-name"`,
					},
					{
						Name:       "podMeta",
						Expression: "object.metadata",
					},
					{
						Name:       "podName",
						Expression: "variables.podMeta.name",
					},
				},
				Validations: []settings.Validation{
					{
						Expression:        "variables.podName != variables.forbiddenName",
						MessageExpression: `variables.forbiddenName + " is forbidden"`,
					},
				},
			},
			object: &corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "pod-name",
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: false,
				Message:  message("pod-name is forbidden"),
				Code:     code(400),
			},
		},
		{
			name: "test URLs library",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: `isURL("http://www.kubewarden.io")`,
					},
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: true,
			},
		},
		{
			name: "test Regex library",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: `"123 abc 456".findAll('[0-9]*', 1) == ['123']`,
					},
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: true,
			},
		},
		{
			name: "test Quantity library",
			settings: settings.Settings{
				Validations: []settings.Validation{
					{
						Expression: `isQuantity("20M")`,
					},
				},
			},
			expectedValidationResponse: kubewardenProtocol.ValidationResponse{
				Accepted: true,
			},
		},
	}

	// Override the host capabilities client with a mock client
	var err error
	host.Client, err = capabilities.NewSuccessfulMockWapcClient(&corev1.Namespace{
		Metadata: &metav1.ObjectMeta{
			Name: "default",
		},
	})
	require.NoError(t, err)

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

			response, err := Validate(payload)
			require.NoError(t, err)

			validationResponse := kubewardenProtocol.ValidationResponse{}
			err = json.Unmarshal(response, &validationResponse)
			require.NoError(t, err)

			assert.Equal(t, test.expectedValidationResponse, validationResponse)
		})
	}
}

// message is a helper function to create a pointer to a string
func message(s string) *string {
	return &s
}

// code is a helper function to create a pointer to a uint16
func code(i uint16) *uint16 {
	return &i
}
