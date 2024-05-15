// nolint: dupl
package library

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	manifestDigest "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest_digest"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
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

func TestOCIGetManifest(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		expectedResult interface{}
	}{
		{
			"kw.oci.getManifest",
			"kw.oci.getManifest('myimage:latest')",
			map[string]interface{}{
				"image": map[string]interface{}{
					"annotations": map[string]interface{}{"annotation": "value"},
					"config": map[string]interface{}{
						"annotations": map[string]interface{}{"annotation": "value"},
						"digest":      "sha256:9e1df6670ac65cbe820f7dffc251cfb13c6fcfea9861c518953dc290f39e7b04",
						"mediaType":   "application/vnd.oci.image.manifest.v1+json",
						"platform": map[string]interface{}{
							"architecture": "amd64",
							"os":           "linux",
						}, "size": float64(1024), "urls": []interface{}{"ghcr.io/kubewarden/policy-server:latest"},
					}, "layers": []interface{}{}, "mediaType": "application/vnd.oci.image.manifest.v1+json", "schemaVersion": float64(0),
				},
				"index": nil,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			host.Client, err = capabilities.NewSuccessfulMockWapcClient(buildMediaTypeManifest())
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

func TestVerifyKeylessExactMatch(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		expectedResult interface{}
	}{
		{
			"kw.oci.verifyKeylessExactMatch empty annotations",
			"kw.oci.verifyKeylessExactMatch('myimage:latest', [KeylessInfo{Issuer: 'foo', Subject: 'bar' }], {})",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
		{
			"kw.oci.verifyKeylessExactMatch empty KeylessInfo",
			"kw.oci.verifyKeylessExactMatch('myimage:latest', [], {})",
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

func TestVerifyKeylessPrefixMatch(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		expectedResult interface{}
	}{
		{
			"kw.oci.verifyKeylessPrefixMatch empty annotations",
			"kw.oci.verifyKeylessPrefixMatch('myimage:latest', [ verify_v2.KeylessPrefixInfo{ Issuer: 'https://github.com/login/oauth', UrlPrefix: 'https://github.com/kubewarden/app-example/.github/workflows/ci.yml@refs/tags/' } ], {})",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
		{
			"kw.oci.verifyKeylessPrefixMatch empty KeylessPrefixInfo",
			"kw.oci.verifyKeylessPrefixMatch('myimage:latest', [], {})",
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

func TestVerifyCertificate(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		expectedResult interface{}
	}{
		{
			"kw.oci.verifyCertificate empty annotations",
			"kw.oci.verifyCertificate('myimage:latest', 'my PEM cert', ['cert_chain1', 'cert_chain2'], false, {})",
			map[string]interface{}{
				"trusted": true,
				"digest":  "myhash",
			},
		},
		{
			"kw.oci.verifyCertificate empty cert chain",
			"kw.oci.verifyCertificate('myimage:latest', 'my PEM cert', [], false, {})",
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
			"kw.oci.getManifest host failure",
			"kw.oci.getManifest('myimage:latest')",
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
		{
			"kw.oci.verifyKeylessExactMatch host failure",
			"kw.oci.verifyKeylessExactMatch('myimage:latest', [ KeylessInfo{ Issuer: 'https://github.com/login/oauth', Subject: 'mail@example.com' } ], {})",
			"cannot verify image: hostcallback error",
		},
		{
			"kw.oci.verifyKeylessPrefixMatch host failure",
			"kw.oci.verifyKeylessPrefixMatch('myimage:latest', [ verify_v2.KeylessPrefixInfo{ Issuer: 'https://github.com/login/oauth', UrlPrefix: 'https://github.com/kubewarden/app-example/.github/workflows/ci.yml@refs/tags/' } ], {})",
			"cannot verify image: hostcallback error",
		},
		{
			"kw.oci.verifyCertificate host failure",
			"kw.oci.verifyCertificate('myimage:latest', 'my PEM cert', ['cert_chain1', 'cert_chain2'], false, {})",
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

func buildMediaTypeManifest() *specs.Manifest {
	return &specs.Manifest{
		MediaType: specs.MediaTypeImageManifest,
		Config: specs.Descriptor{
			MediaType:   specs.MediaTypeImageManifest,
			Digest:      digest.FromString("mydummydigest"),
			Size:        1024,
			URLs:        []string{"ghcr.io/kubewarden/policy-server:latest"},
			Annotations: map[string]string{"annotation": "value"},
			Platform: &specs.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
		Layers:      []specs.Descriptor{},
		Annotations: map[string]string{"annotation": "value"},
	}
}
