package library

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
	verify "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/verify_v2"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	"github.com/stretchr/testify/require"
)

func TestSigstore(t *testing.T) {
	tests := []struct {
		name              string
		expression        string
		expectedOperation string
		expectedRequest   interface{}
		response          interface{}
		expectedResult    interface{}
	}{
		{
			"pubKey verifier",
			"kw.sigstore.image('image:latest').annotation('foo', 'bar').pubKey('key').pubKey('otherKey').verify().isTrusted()",
			"v2/verify",
			verify.SigstorePubKeysVerify{
				Image:       "image:latest",
				PubKeys:     []string{"key", "otherKey"},
				Annotations: map[string]string{"foo": "bar"},
			},
			oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "sha256:1234",
			},
			true,
		},
		{
			"kelyess verifier",
			"kw.sigstore.image('image:latest').annotation('foo', 'bar').keyless('issuer', 'subject').keyless('otherIssuer', 'otherSubject').verify().digest()",
			"v2/verify",
			verify.SigstoreKeylessVerifyExact{
				Image:   "image:latest",
				Keyless: []oci.KeylessInfo{{Issuer: "issuer", Subject: "subject"}, {Issuer: "otherIssuer", Subject: "otherSubject"}},
				Annotations: map[string]string{
					"foo": "bar",
				},
			},
			oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "sha256:1234",
			},
			"sha256:1234",
		},
		{
			"keylessPrefix verifier",
			"kw.sigstore.image('image:latest').annotation('foo', 'bar').keylessPrefix('issuer', 'subject').keylessPrefix('otherIssuer', 'otherSubject').verify().isTrusted()",
			"v2/verify",
			verify.SigstoreKeylessPrefixVerify{
				Image:         "image:latest",
				KeylessPrefix: []verify.KeylessPrefixInfo{{Issuer: "issuer", UrlPrefix: "subject"}, {Issuer: "otherIssuer", UrlPrefix: "otherSubject"}},
				Annotations: map[string]string{
					"foo": "bar",
				},
			},
			oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "sha256:1234",
			},
			true,
		},
		{
			"github action verifier (owner and repo)",
			"kw.sigstore.image('image:latest').annotation('foo', 'bar').githubAction('kubewarden', 'policy-server').verify().digest()",
			"v2/verify",
			verify.SigstoreGithubActionsVerify{
				Image: "image:latest",
				Owner: "kubewarden",
				Repo:  "policy-server",
				Annotations: map[string]string{
					"foo": "bar",
				},
			},
			oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "sha256:1234",
			},
			"sha256:1234",
		},
		{
			"github action verifier (owner)",
			"kw.sigstore.image('image:latest').annotation('foo', 'bar').githubAction('kubewarden').verify().digest()",
			"v2/verify",
			verify.SigstoreGithubActionsVerify{
				Image: "image:latest",
				Owner: "kubewarden",
				Annotations: map[string]string{
					"foo": "bar",
				},
			},
			oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "sha256:1234",
			},
			"sha256:1234",
		},
		{
			"certificate verifier",
			"kw.sigstore.image('image:latest').annotation('foo', 'bar').certificate('cert').certificateChain('chain1').certificateChain('chain2').requireRekorBundle(true).verify().isTrusted()",
			"v2/verify",
			verify.SigstoreCertificateVerify{
				Image:       "image:latest",
				Certificate: []rune("cert"),
				CertificateChain: [][]rune{
					[]rune("chain1"),
					[]rune("chain2"),
				},
				RequireRekorBundle: true,
				Annotations:        map[string]string{"foo": "bar"},
			},
			oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "sha256:1234",
			},
			true,
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
				Sigstore(),
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
