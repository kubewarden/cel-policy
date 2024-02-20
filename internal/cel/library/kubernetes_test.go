package library

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/stretchr/testify/require"
)

func TestKubernetes(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		response       interface{}
		expectedResult interface{}
	}{
		{
			"kw.k8s.listResourcesByNamespace",
			"kw.k8s.listResourcesByNamespace(ListResourcesByNamespaceRequest{Namespace: 'default'}).items[0].kind",
			map[string]interface{}{
				"items": []interface{}{
					&corev1.Pod{
						Kind: "Pod",
						Metadata: &metav1.ObjectMeta{
							Name:      "nginx",
							Namespace: "default",
						},
					},
					&corev1.Service{
						Kind: "Service",
						Metadata: &metav1.ObjectMeta{
							Name:      "pgsql",
							Namespace: "default",
						},
					},
				},
			},
			"Pod",
		},
		{
			"kw.k8s.listAllResources",
			"kw.k8s.listAllResources(ListAllResourcesRequest{Kind: 'Pod'}).items[0].metadata.name",
			&corev1.PodList{
				Items: []*corev1.Pod{
					{
						Metadata: &metav1.ObjectMeta{
							Name: "nginx",
						},
					},
					{
						Metadata: &metav1.ObjectMeta{
							Name: "pgsql",
						},
					},
				},
			},
			"nginx",
		},
		{
			"kw.k8s.getResource",
			"kw.k8s.getResource(GetResourceRequest{Kind: 'Pod'}).metadata.name",
			&corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Name: "nginx",
				},
			},
			"nginx",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			host.Client, err = capabilities.NewSuccessfulMockWapcClient(test.response)
			require.NoError(t, err)

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

func TestKubernetesHostFailure(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		errorString string
	}{
		{
			"kw.k8s.listAllResources host failure",
			"kw.k8s.listAllResources(ListAllResourcesRequest{Kind: 'Pod'})",
			"cannot list all Kubernetes resources: hostcallback error",
		},
		{
			"kw.k8s.listResourcesByNamespace host failure",
			"kw.k8s.listResourcesByNamespace(ListResourcesByNamespaceRequest{Namespace: 'default'})",
			"cannot list Kubernetes resources by namespace: hostcallback error",
		},
		{
			"kw.k8s.getResource host failure",
			"kw.k8s.getResource(GetResourceRequest{Kind: 'Pod'}).metadata.name",
			"cannot get Kubernetes resource: hostcallback error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error

			host.Client = capabilities.NewFailingMockWapcClient(fmt.Errorf("hostcallback error"))

			env, err := cel.NewEnv(
				Kubernetes(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast)
			require.NoError(t, err)

			_, _, err = prog.Eval(map[string]interface{}{})
			require.Error(t, err)
			require.Equal(t, test.errorString, err.Error())
		})
	}
}
