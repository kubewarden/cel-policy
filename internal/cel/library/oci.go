package library

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	manifestDigest "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest_digest"
	verifyV2 "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/verify_v2"
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
//
// # OCI.VerifyPubKeysImage
//
// This CEL function verifies sigstore signatures of an image using public keys.
// Usage in CEL:
//
//	OCI.verifyPubKeysImage(<string>, <list<string>>, map(<string>)<string>) -> <bool, string>
//
// Returns a map(<string>) with 2 fields:
//   - "trusted": <bool> informs if the image passed verification or not
//   - "digest": <string> digest of the verified image

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

		cel.Function("kw.oci.verifyPubKeysImage",
			cel.Overload("kw_oci_verify_pub_keys_image",
				[]*cel.Type{
					cel.StringType,
					cel.ListType(cel.StringType),
					cel.MapType(cel.StringType, cel.StringType),
				},
				cel.DynType,
				cel.FunctionBinding(verifyPubKeysImage),
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
func verifyPubKeysImage(args ...ref.Val) ref.Val {
	image, ok1 := args[0].Value().(string)
	if !ok1 {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	pubKeys, ok2 := args[1].(traits.Lister)
	if !ok2 {
		return types.MaybeNoSuchOverloadErr(args[1])
	}
	pubKeysList, err := pubKeys.ConvertToNative(reflect.TypeOf([]string{}))
	if err != nil {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	annotations, ok3 := args[2].(traits.Mapper)
	if !ok3 {
		return types.MaybeNoSuchOverloadErr(args[2])
	}
	annotationsMap, err := annotations.ConvertToNative(reflect.TypeOf(map[string]string{}))
	if err != nil {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	response, err := verifyV2.VerifyPubKeysImage(&host, image, pubKeysList.([]string), annotationsMap.(map[string]string))
	if err != nil {
		return types.NewErr("cannot verify image: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, map[string]any{
		"trusted": response.IsTrusted,
		"digest":  response.Digest,
	})
}
