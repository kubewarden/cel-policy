package library

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	manifestDigest "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest_digest"

	"github.com/stretchr/testify/require"
)

func TestOCIGetManifestDigest(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		response       string
		expectedResult string
	}{
		{
			"kw.oci.getManifestDigest",
			"kw.oci.getManifestDigest('myimage:latest')",
			"myhash",
			"myhash",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			host.Client, err = capabilities.NewSuccessfulMockWapcClient(manifestDigest.OciManifestResponse{
				Digest: test.response,
			})
			require.NoError(t, err)

			env, err := cel.NewEnv(
				OCI(),
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

func TestOCIHostFailure(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{
			"kw.oci.getManifestDigest host failure",
			"kw.oci.getManifestDigest('myimage:latest')",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			host.Client = capabilities.NewFailingMockWapcClient(fmt.Errorf("hostcallback error"))

			env, err := cel.NewEnv(
				OCI(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast)
			require.NoError(t, err)

			_, _, err = prog.Eval(map[string]interface{}{})
			require.Error(t, err)
			require.Equal(t, "cannot get oci manifest: hostcallback error", err.Error())
		})
	}
}
