// nolint: dupl
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

			prog, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
			require.NoError(t, err)

			val, _, err := prog.Eval(map[string]interface{}{})
			require.NoError(t, err)

			result, err := val.ConvertToNative(reflect.TypeOf(test.expectedResult))
			require.NoError(t, err)

			require.Equal(t, test.expectedResult, result)
		})
	}
}

func TestVerifyPubKeysImage(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		expectedResult interface{}
	}{
		{
			"kw.oci.verifyPubKeysImage empty annotations",
			"kw.oci.verifyPubKeysImage('myimage:latest', ['pubkey1', 'pubkey2'], {} )",
			map[string]interface{}{
				"digest":  "myhash",
				"trusted": true,
			},
		},
		{
			"kw.oci.verifyPubKeysImage",
			"kw.oci.verifyPubKeysImage('myimage:latest', ['pubkey1', 'pubkey2'], {'foo': 'bar'} )",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error

			host.Client, err = capabilities.NewSuccessfulMockWapcClient(
				map[string]interface{}{
					"is_trusted": true,
					"digest":     "myhash",
				},
			)
			require.NoError(t, err)

			env, err := cel.NewEnv(
				OCI(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
			require.NoError(t, err)

			val, _, err := prog.Eval(map[string]interface{}{})
			require.NoError(t, err)

			result, err := val.ConvertToNative(reflect.TypeOf(test.expectedResult))
			require.NoError(t, err)

			require.Equal(t, test.expectedResult, result)
		})
	}
}

func TestVerifyKeylessGithubActions(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		expectedResult interface{}
	}{
		{
			"kw.oci.verifyKeylessGithubActions empty annotations",
			"kw.oci.verifyKeylessGithubActions('myimage:latest', 'octocat', 'example-repo', {})",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
		{
			"kw.oci.verifyKeylessGithubActions empty repo",
			"kw.oci.verifyKeylessGithubActions('myimage:latest', 'octocat', '', {'foo': 'bar'})",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
		{
			"kw.oci.verifyKeylessGithubActions",
			"kw.oci.verifyKeylessGithubActions('myimage:latest', 'octocat', 'example-repo', {'foo': 'bar'})",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error

			host.Client, err = capabilities.NewSuccessfulMockWapcClient(
				map[string]interface{}{
					"is_trusted": true,
					"digest":     "myhash",
				},
			)
			require.NoError(t, err)

			env, err := cel.NewEnv(
				OCI(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
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
		expected   string
	}{
		{
			"kw.oci.getManifestDigest host failure",
			"kw.oci.getManifestDigest('myimage:latest')",
			"cannot get oci manifest: hostcallback error",
		},
		{
			"kw.oci.verifyPubKeysImage host failure",
			"kw.oci.verifyPubKeysImage('myimage:latest', ['pubkey1', 'pubkey2'], {})",
			"cannot verify image: hostcallback error",
		},
		{
			"kw.oci.verifyKeylessGithubActions host failure",
			"kw.oci.verifyKeylessGithubActions('myimage:latest', 'octocat', 'example-repo', {})",
			"cannot verify image: hostcallback error",
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

			prog, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
			require.NoError(t, err)

			_, _, err = prog.Eval(map[string]interface{}{})
			require.Error(t, err)
			require.Equal(t, test.expected, err.Error())
		})
	}
}
