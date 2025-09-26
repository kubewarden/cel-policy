package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/kubewarden/cel-policy/internal/settings"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	kubewardenProtocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/admissionregistration"
)

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
			name: "paramref with no namespace should use request namespace",
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

// This test covers various combinations of failurePolicy and parameterNotFoundAction
// settings, and checks that the policy behaves in the same way that Kubernetes would do.
func TestParamFetchBehaviour(t *testing.T) {
	validationRejectionMessage := "not true"
	rejectionResponse := kubewardenProtocol.ValidationResponse{
		Accepted: false,
		Message:  message(validationRejectionMessage),
		Code:     code(400),
	}
	rejectionResponseParamsNotFound := kubewardenProtocol.ValidationResponse{
		Accepted: false,
		Message:  message("failed to get params for performing policy evaluation: no parameters found"),
		Code:     code(400),
	}
	rejectionResponseHostCallFailed := kubewardenProtocol.ValidationResponse{
		Accepted: false,
		Message:  message("failed to get params for performing policy evaluation: cannot list Kubernetes resources: Host call failed"),
		Code:     code(400),
	}
	acceptanceResponse := kubewardenProtocol.ValidationResponse{
		Accepted: true,
	}
	tests := []struct {
		invalidResource            bool
		paramsFound                bool
		failurePolicy              admissionregistration.FailurePolicyType
		paramNotFoundAction        admissionregistration.ParameterNotFoundActionType
		expectedValidationResponse kubewardenProtocol.ValidationResponse
		failedHostCall             bool
	}{
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            true,
			paramsFound:                false,
			expectedValidationResponse: rejectionResponseHostCallFailed,
			failedHostCall:             true,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            true,
			paramsFound:                true,
			expectedValidationResponse: rejectionResponse,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            false,
			paramsFound:                true,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            true,
			paramsFound:                false,
			expectedValidationResponse: rejectionResponseParamsNotFound,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            false,
			paramsFound:                false,
			expectedValidationResponse: rejectionResponseParamsNotFound,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            true,
			paramsFound:                true,
			expectedValidationResponse: rejectionResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            false,
			paramsFound:                true,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            true,
			paramsFound:                false,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.DenyAction,
			invalidResource:            false,
			paramsFound:                false,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            true,
			paramsFound:                true,
			expectedValidationResponse: rejectionResponse,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            false,
			paramsFound:                true,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            true,
			paramsFound:                false,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Fail,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            false,
			paramsFound:                false,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            true,
			paramsFound:                true,
			expectedValidationResponse: rejectionResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            false,
			paramsFound:                true,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            true,
			paramsFound:                false,
			expectedValidationResponse: acceptanceResponse,
		},
		{
			failurePolicy:              admissionregistration.Ignore,
			paramNotFoundAction:        admissionregistration.AllowAction,
			invalidResource:            false,
			paramsFound:                false,
			expectedValidationResponse: acceptanceResponse,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("failurePolicy=%s-paramNotFoundAction=%s-invalidResouce=%t-paramsFound=%t-hostCallFailed=%t", test.failurePolicy, test.paramNotFoundAction, test.invalidResource, test.paramsFound, test.failedHostCall), func(t *testing.T) {
			invalidPodName := "invalid-pod-name"
			validPodName := "valid-pod-name"
			mockWapcClient := &mocks.MockWapcClient{}
			mockWapcClient.Test(t)

			settings := settings.Settings{
				FailurePolicy: test.failurePolicy,
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ParamRef: &admissionregistration.ParamRef{
					Selector: &k8smetav1.LabelSelector{
						MatchLabels: map[string]string{
							"environment": "test",
						},
					},
					ParameterNotFoundAction: &test.paramNotFoundAction,
				},
				Validations: []settings.Validation{
					{
						Expression: "object.metadata.name == params.data.name",
						Message:    validationRejectionMessage,
					},
				},
			}

			expectedLabelSelector, err := formatLabelSelectorString(settings.ParamRef.Selector)
			require.NoError(t, err)
			listRequest, err := json.Marshal(&kubernetes.ListResourcesByNamespaceRequest{
				APIVersion:    "v1",
				Kind:          "ConfigMap",
				Namespace:     "test",
				LabelSelector: &expectedLabelSelector,
			})
			require.NoError(t, err)

			var paramsReturned k8scorev1.ConfigMapList
			if test.paramsFound {
				paramsReturned = k8scorev1.ConfigMapList{
					Items: []k8scorev1.ConfigMap{
						{
							ObjectMeta: k8smetav1.ObjectMeta{
								Name:      "config-1",
								Namespace: "test",
								Labels: map[string]string{
									"environment": "test",
								},
							},
							Data: map[string]string{
								"name": validPodName,
							},
						},
					},
				}
			} else {
				paramsReturned = k8scorev1.ConfigMapList{
					Items: []k8scorev1.ConfigMap{},
				}
			}

			listResponse, err := json.Marshal(paramsReturned)
			require.NoError(t, err)

			// Override the host capabilities client with a mock client
			request, err := json.Marshal(&kubernetes.GetResourceRequest{
				APIVersion: "v1",
				Kind:       "Namespace",
				Name:       "test",
			})
			require.NoError(t, err)

			response, err := json.Marshal(&corev1.Namespace{
				Metadata: &metav1.ObjectMeta{
					Name: "test",
					Labels: map[string]string{
						"foo": "bar",
					},
				},
			})
			require.NoError(t, err)

			var listResponseError error
			if test.failedHostCall {
				listResponseError = errors.New("Host call failed")
				listResponse = nil
			}

			mockWapcClient.
				On("HostCall", "kubewarden", "kubernetes", "list_resources_by_namespace", listRequest).Return(listResponse, listResponseError).
				On("HostCall", "kubewarden", "kubernetes", "get_resource", request).Return(response, nil)
			host.Client = mockWapcClient

			object := corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name:      validPodName,
					Namespace: "test",
				},
			}
			if test.invalidResource {
				object.Metadata.Name = invalidPodName
			}

			objectJSON, err := json.Marshal(object)
			require.NoError(t, err)

			settingsJSON, err := json.Marshal(settings)
			require.NoError(t, err)

			validationRequest := kubewardenProtocol.ValidationRequest{
				Request: kubewardenProtocol.KubernetesAdmissionRequest{
					Namespace: "test",
					Object:    objectJSON,
				},
				Settings: settingsJSON,
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
