package library

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/net"
)

// Net returns a cel.EnvOption to configure namespaced network host-callback
// Kubewarden functions.
//
// # Net.LookupHost
//
// This CEL function looks up the addresses for a given hostname via DNS. It
// returns the addresses as a list of strings.
//
// Usage in CEL:
//
//	net.lookupHost(<string>) -> <list<string>>
//
// Example:
//
//	kw.net.lookupHost('kubewarden')
func Net() cel.EnvOption {
	return cel.Lib(netLib{})
}

type netLib struct{}

// LibraryName implements the SingletonLibrary interface method.
func (netLib) LibraryName() string {
	return "kw.net"
}

// CompileOptions implements the Library interface method.
func (netLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// group every binding under a container to simplify usage
		cel.Container("net"),

		ext.NativeTypes(reflect.TypeOf(&net.LookupHostResponse{})),

		cel.Function("kw.net.lookupHost",
			cel.Overload("kw_net_lookup_host",
				[]*cel.Type{cel.StringType},  // receives <string>
				cel.ListType(cel.StringType), // returns <list<string>, or error
				cel.UnaryBinding(lookupHost),
			),
		),
	}
}

// ProgramOptions implements the Library interface method.
func (netLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func lookupHost(arg ref.Val) ref.Val {
	hostname, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	responseArray, err := net.LookupHost(&host, hostname)
	if err != nil {
		return types.NewErr("cannot lookup host: %s", err)
	}

	return types.NewStringList(types.DefaultTypeAdapter, responseArray)
}
