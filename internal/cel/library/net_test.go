//nolint:dupl
package library

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	netCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/net"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	"github.com/stretchr/testify/require"
)

func TestNet(t *testing.T) {
	tests := []struct {
		name              string
		expression        string
		expectedOperation string
		expectedRequest   interface{}
		response          interface{}
		expectedResult    interface{}
	}{
		{
			"lookupHost",
			"kw.net.lookupHost('example.com')",
			"v1/dns_lookup_host",
			"example.com",
			netCap.LookupHostResponse{
				Ips: []string{"1.1.1.1", "2.2.2.2"},
			},
			[]string{"1.1.1.1", "2.2.2.2"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := json.Marshal(test.response)
			require.NoError(t, err)

			expectedRequest, err := json.Marshal(test.expectedRequest)
			require.NoError(t, err)

			mockWapcClient := &mocks.MockWapcClient{}
			mockWapcClient.On("HostCall", "kubewarden", "net", test.expectedOperation, expectedRequest).Return(response, nil)

			host.Client = mockWapcClient

			env, err := cel.NewEnv(
				Net(),
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
