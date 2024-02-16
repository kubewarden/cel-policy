package library

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/net"
	"github.com/stretchr/testify/require"
)

func TestNet(t *testing.T) {
	tests := []struct {
		name           string
		expression     string
		response       []string
		expectedResult interface{}
	}{
		{
			"kw.net.lookupHost",
			"kw.net.lookupHost('kubewarden')",
			[]string{"192.168.0.1", "10.0.0.1"},
			[]string{"192.168.0.1", "10.0.0.1"},
		},
		{
			"kw.net.lookupHost test return type",
			"kw.net.lookupHost('kubewarden')[0]",
			[]string{"192.168.0.1", "10.0.0.1"},
			"192.168.0.1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error

			host.Client, err = capabilities.NewSuccessfulMockWapcClient(net.LookupHostResponse{Ips: test.response})
			require.NoError(t, err)

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

func TestNetHostFailure(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{
			"kw.net.lookupHost",
			"kw.net.lookupHost('kubewarden')",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error

			host.Client = capabilities.NewFailingMockWapcClient(fmt.Errorf("hostcallback error"))

			env, err := cel.NewEnv(
				Net(),
			)
			require.NoError(t, err)

			ast, issues := env.Compile(test.expression)
			require.Empty(t, issues)

			prog, err := env.Program(ast)
			require.NoError(t, err)

			_, _, err = prog.Eval(map[string]interface{}{})
			require.Error(t, err)
			require.Equal(t, "cannot lookup host: hostcallback error", err.Error())
		})
	}
}
