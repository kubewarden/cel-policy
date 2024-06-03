package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	netCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/net"
)

// Net provides a CEL function library extension to interact with Kubewarden's network capabilities.
//
// lookupHost
//
// Returns a list of IP addresses resolved from the provided hostname.
//
//	kw.net.lookupHost(<string>) <list<string>>
//
// Examples:
//
//	kw.net.lookupHost('example.com') // returns a list of IP addresses associated with 'example.com'
func Net() cel.EnvOption {
	return cel.Lib(netLib{})
}

type netLib struct{}

func (netLib) LibraryName() string {
	return "kw.net"
}

func (netLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("kw.net.lookupHost",
			cel.Overload("kw_net_lookup_host",
				[]*cel.Type{cel.StringType},
				cel.ListType(cel.StringType),
				cel.UnaryBinding(lookupHost),
			),
		),
	}
}

func (netLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func lookupHost(arg ref.Val) ref.Val {
	hostname, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	response, err := netCap.LookupHost(&host, hostname)
	if err != nil {
		return types.NewErr("cannot lookup host: %s", err)
	}

	return types.NewStringList(types.DefaultTypeAdapter, response)
}
