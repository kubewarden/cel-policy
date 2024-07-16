package library

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/kubernetes"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	"github.com/stretchr/testify/require"
)

func TestKubernetes(t *testing.T) {
	tests := []struct {
		name              string
		expression        string
		expectedOperation string
		expectedRequest   interface{}
		response          interface{}
		expectedResult    interface{}
	}{
		{
			"list",
			"kw.k8s.apiVersion('v1').kind('Pod').labelSelector('foo=bar').list().items[1].metadata.name",
			"list_resources_all",
			kubernetes.ListAllResourcesRequest{
				APIVersion:    "v1",
				Kind:          "Pod",
				LabelSelector: stringPtr("foo=bar"),
				FieldSelector: nil,
			},
			&corev1.PodList{
				Items: []*corev1.Pod{
					{
						Kind: "Pod",
						Metadata: &metav1.ObjectMeta{
							Name:      "app1",
							Namespace: "default",
						},
					},
					{
						Kind: "Pod",
						Metadata: &metav1.ObjectMeta{
							Name:      "app2",
							Namespace: "other",
						},
					},
				},
			},
			"app2",
		},
		{
			"list (namespace)",
			"kw.k8s.apiVersion('v1').kind('Pod').fieldSelector('foo.bar=baz').namespace('default').list().items[0].metadata.name",
			"list_resources_by_namespace",
			kubernetes.ListResourcesByNamespaceRequest{
				APIVersion:    "v1",
				Kind:          "Pod",
				Namespace:     "default",
				LabelSelector: nil,
				FieldSelector: stringPtr("foo.bar=baz"),
			},
			&corev1.PodList{
				Items: []*corev1.Pod{
					{
						Kind: "Pod",
						Metadata: &metav1.ObjectMeta{
							Name:      "app1",
							Namespace: "default",
						},
					},
					{
						Kind: "Pod",
						Metadata: &metav1.ObjectMeta{
							Name:      "app2",
							Namespace: "default",
						},
					},
				},
			},
			"app1",
		},
		{
			"get",
			"kw.k8s.apiVersion('v1').kind('Pod').namespace('default').get('app').metadata.labels.foo",
			"get_resource",
			kubernetes.GetResourceRequest{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       "app",
				Namespace:  stringPtr("default"),
			},
			&corev1.Pod{
				Kind: "Pod",
				Metadata: &metav1.ObjectMeta{
					Labels: map[string]string{
						"foo": "bar",
					},
					Name:      "app",
					Namespace: "default",
				},
			},
			"bar",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := json.Marshal(test.response)
			require.NoError(t, err)

			expectedRequest, err := json.Marshal(test.expectedRequest)
			require.NoError(t, err)

			mockWapcClient := &mocks.MockWapcClient{}
			mockWapcClient.On("HostCall", "kubewarden", "kubernetes", test.expectedOperation, expectedRequest).Return(response, nil)

			host.Client = mockWapcClient

			env, err := cel.NewEnv(
				Kubernetes(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast)
			require.NoError(t, err)

			val, _, err := prog.Eval(map[string]interface{}{})
			require.NoError(t, err)

			result, err := val.ConvertToNative(reflect.TypeOf(test.expectedResult))
			require.NoError(t, err)

			require.Equal(t, test.expectedResult, result)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
