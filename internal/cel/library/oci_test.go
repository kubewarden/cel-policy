package library

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	mocks "github.com/kubewarden/cel-policy/mocks/github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	manifestCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest"
	manifestDigestCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest_digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestOCI(t *testing.T) {
	tests := []struct {
		name              string
		expression        string
		expectedOperation string
		expectedRequest   interface{}
		response          interface{}
		expectedResult    interface{}
	}{
		{
			"manifest",
			"kw.oci.image('image:latest').manifest().image.mediaType",
			"v1/oci_manifest",
			"image:latest",
			manifestCap.OciImageManifestResponse{
				Image: &specs.Manifest{
					MediaType: specs.MediaTypeImageManifest,
				},
			},
			specs.MediaTypeImageManifest,
		},
		{
			"manifestDigest",
			"kw.oci.image('image:latest').manifestDigest()",
			"v1/manifest_digest",
			"image:latest",
			manifestDigestCap.OciManifestResponse{
				Digest: "sha256:1234",
			},
			"sha256:1234",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := json.Marshal(test.response)
			require.NoError(t, err)

			expectedRequest, err := json.Marshal(test.expectedRequest)
			require.NoError(t, err)

			mockWapcClient := &mocks.MockWapcClient{}
			mockWapcClient.On("HostCall", "kubewarden", "oci", test.expectedOperation, expectedRequest).Return(response, nil)

			host.Client = mockWapcClient

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
