package library

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	cryptoCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/crypto"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	"github.com/stretchr/testify/require"
)

func TestCrypto(t *testing.T) {
	tests := []struct {
		name              string
		expression        string
		expectedOperation string
		expectedRequest   interface{}
		response          interface{}
		expectedResult    interface{}
	}{
		{
			"verify",
			"kw.crypto.certificate('cert.pem').certificateChain('chain1.pem').certificateChain('chain2.pem').notAfter(timestamp('2000-01-01T00:00:00Z')).verify().isTrusted()",
			"v1/is_certificate_trusted",
			cryptoCap.CertificateVerificationRequest{
				Cert: cryptoCap.Certificate{
					Encoding: cryptoCap.Pem,
					Data:     []rune("cert.pem"),
				},
				CertChain: []cryptoCap.Certificate{
					{
						Encoding: cryptoCap.Pem,
						Data:     []rune("chain1.pem"),
					},
					{
						Encoding: cryptoCap.Pem,
						Data:     []rune("chain2.pem"),
					},
				},
				NotAfter: "2000-01-01T00:00:00Z",
			},
			&cryptoCap.CertificateVerificationResponse{
				Trusted: true,
				Reason:  "",
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
			mockWapcClient.On("HostCall", "kubewarden", "crypto", test.expectedOperation, expectedRequest).Return(response, nil)

			host.Client = mockWapcClient

			env, err := cel.NewEnv(
				Crypto(),
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
