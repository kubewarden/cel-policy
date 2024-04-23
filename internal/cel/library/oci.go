package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	manifestDigest "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest_digest"
)

// OCI returns a cel.EnvOption to configure OCI-related host-callback
// Kubewarden functions.
//
//
// # OCI.GetOCIManifestDigest
//
// Returns the digest of an OCI manifest. Can be used to get the immutable
// reference of a container image or anything stored in an OCI registry (Helm
// charts, Kubewarden policies..).
// Usage in CEL:
//
// kw.oci.getManifestDigest(<string>) -> <string>
//
// Example:
//
// kw.oci.getManifestDigest('myimage')

func OCI() cel.EnvOption {
	return cel.Lib(ociLib{})
}

type ociLib struct{}

// LibraryName implements the SingletonLibrary interface method.
func (ociLib) LibraryName() string {
	return "kw.oci"
}

// CompileOptions implements the Library interface method.
func (ociLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// group every binding under a container to simplify usage
		cel.Container("oci"),

		cel.Function("kw.oci.getManifestDigest",
			cel.Overload("kw_oci_get_manifest_digest",
				[]*cel.Type{cel.StringType}, // receives <string>
				cel.StringType,              // returns <string>, or error
				cel.UnaryBinding(getManifestDigest),
			),
		),
	}
}

// ProgramOptions implements the Library interface method.
func (ociLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func getManifestDigest(arg ref.Val) ref.Val {
	image, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	digest, err := manifestDigest.GetOCIManifestDigest(&host, image)
	if err != nil {
		return types.NewErr("cannot get oci manifest: %s", err)
	}

	return types.String(digest)
}
