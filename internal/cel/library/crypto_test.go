package library

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/crypto"
	"github.com/stretchr/testify/require"
)

func TestCrypto(t *testing.T) {
	tests := []struct {
		name            string
		expression      string
		responseTrusted bool
		responseReason  string
		expectedResult  any
	}{
		{
			"kw.crypto.verifyCert",
			"kw.crypto.verifyCert(" +
				"'---BEGIN CERTIFICATE---foo---END CERTIFICATE---'," +
				"[ '---BEGIN CERTIFICATE---bar---END CERTIFICATE---' ]," +
				"'2030-08-15T16:23:42+00:00'" +
				")",
			false,
			"the certificate is expired",
			map[string]any{
				"trusted": false,
				"reason":  "the certificate is expired",
			},
		},
		{
			"kw.crypto.verifyCert with empty CertChain",
			"kw.crypto.verifyCert( " +
				"'---BEGIN CERTIFICATE---foo2---END CERTIFICATE---'," +
				"[]," +
				"'0004-08-15T16:23:42+00:00'" +
				")",
			true, // e.g: cert is past expiration date, yet is trusted (empty CertChain)
			"",
			map[string]any{
				"trusted": true,
				"reason":  "",
			},
		},
		{
			"kw.crypto.verifyCert return type",
			"kw.crypto.verifyCert(  " +
				"'---BEGIN CERTIFICATE---foo2---END CERTIFICATE---'," +
				"[]," +
				"'0004-08-15T16:23:42+00:00'" +
				").trusted",
			true, // e.g: cert is past expiration date, yet is trusted (empty CertChain)
			"",
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			host.Client, err = capabilities.NewSuccessfulMockWapcClient(crypto.CertificateVerificationResponse{
				Trusted: test.responseTrusted,
				Reason:  test.responseReason,
			})
			require.NoError(t, err)

			env, err := cel.NewEnv(
				Crypto(),
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

func TestCryptoHostFailure(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{
			"kw.crypto.verifyCert host failure",
			"kw.crypto.verifyCert( " +
				"'---BEGIN CERTIFICATE---foo3---END CERTIFICATE---'," +
				"[ '---BEGIN CERTIFICATE---bar3---END CERTIFICATE---' ]," +
				"'2030-08-15T16:23:42+00:00'" +
				")",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			host.Client = capabilities.NewFailingMockWapcClient(fmt.Errorf("hostcallback error"))

			env, err := cel.NewEnv(
				Crypto(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
			require.NoError(t, err)

			_, _, err = prog.Eval(map[string]interface{}{})
			require.Error(t, err)
			require.Equal(t, "cannot verify certificate: hostcallback error", err.Error())
		})
	}
}
