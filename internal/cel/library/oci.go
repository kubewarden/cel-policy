package library

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
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
//
// # OCI.VerifyKeylessGithubActions
//
// Verify sigstore signatures of an image using keyless signatures made via Github
// Actions.
// Usage in CEL:
//
//	OCI.VerifyKeylessGithubActions(<string>, <string>, <string>, map(<string>)<string>) -> <bool, string>
//
// Arguments:
// * `image` - image to be verified
// * `owner` - owner of the repository. E.g: octocat
// * `repo` - Optional. repo of the GH Action workflow that signed the artifact. E.g: example-repo. Optional.
// * `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
//
// # OCI.VerifyKeylessExactMatch
//
// Verify sigstore signatures of an image using keyless signing
// Usage in CEL:
//
//	OCI.VerifyKeylessExactMatch(<string>, <list(oci.KeylessInfo{Issuer: <string>, Subject: <string>})>, map(<string>)<string>) -> <bool, string>
//
// Arguments:
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
// * keyless: list of KeylessInfo pairs, containing Issuer and Subject info from OIDC providers
// * annotations: annotations that must have been provided by all signers when they signed the OCI artifact

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

		ext.NativeTypes(reflect.TypeOf(&oci.KeylessInfo{})),
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

		cel.Function("kw.oci.verifyKeylessGithubActions",
			cel.Overload("kw_oci_verify_keyless_github_actions",
				[]*cel.Type{
					cel.StringType,
					cel.StringType,
					cel.StringType,
					cel.MapType(cel.StringType, cel.StringType),
				},
				cel.DynType,
				cel.FunctionBinding(verifyKeylessGithubActions),
			),
		),

		cel.Function("kw.oci.verifyKeylessExactMatch",
			cel.Overload("kw_oci_verify_keyless_exact_match",
				[]*cel.Type{
					cel.StringType,
					cel.ListType(cel.ObjectType("oci.KeylessInfo")),
					cel.MapType(cel.StringType, cel.StringType),
				},
				cel.DynType,
				cel.FunctionBinding(verifyKeylessExactMatch),
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

func verifyKeylessGithubActions(args ...ref.Val) ref.Val {
	image, ok1 := args[0].Value().(string)
	if !ok1 {
		return types.MaybeNoSuchOverloadErr(args[0])
	}
	owner, ok2 := args[1].Value().(string)
	if !ok2 {
		return types.MaybeNoSuchOverloadErr(args[1])
	}
	// this is optional, can be empty
	repo, ok3 := args[2].Value().(string)
	if !ok3 {
		return types.MaybeNoSuchOverloadErr(args[2])
	}
	annotations, ok4 := args[3].(traits.Mapper)
	if !ok4 {
		return types.MaybeNoSuchOverloadErr(args[3])
	}
	annotationsMap, err := annotations.ConvertToNative(reflect.TypeOf(map[string]string{}))
	if err != nil {
		return types.MaybeNoSuchOverloadErr(args[3])
	}

	response, err := verifyV2.VerifyKeylessGithubActions(&host, image, owner, repo, annotationsMap.(map[string]string))
	if err != nil {
		return types.NewErr("cannot verify image: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, map[string]any{
		"trusted": response.IsTrusted,
		"digest":  response.Digest,
	})
}

func verifyKeylessExactMatch(args ...ref.Val) ref.Val { // nolint: dupl
	image, ok1 := args[0].Value().(string)
	if !ok1 {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	keyless, ok2 := args[1].(traits.Lister)
	if !ok2 {
		return types.MaybeNoSuchOverloadErr(args[1])
	}
	keylessLength, ok := keyless.Size().(types.Int)
	if !ok {
		return types.NewErr("cannot convert keyless info length to int")
	}
	keylessList := make([]oci.KeylessInfo, 0, keylessLength)
	for i := types.Int(0); i < keylessLength; i++ {
		elem, err := keyless.Get(i).ConvertToNative(reflect.TypeOf(oci.KeylessInfo{}))
		if err != nil {
			return types.NewErr("cannot convert keyless info: %s", err)
		}
		elemKeylessInfo, ok := elem.(oci.KeylessInfo)
		if !ok {
			return types.NewErr("cannot convert keyless info length to int")
		}
		keylessList = append(keylessList, elemKeylessInfo)
	}

	annotations, ok4 := args[2].(traits.Mapper)
	if !ok4 {
		return types.MaybeNoSuchOverloadErr(args[2])
	}
	annotationsMap, err := annotations.ConvertToNative(reflect.TypeOf(map[string]string{}))
	if err != nil {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	response, err := verifyV2.VerifyKeylessExactMatch(&host, image, keylessList, annotationsMap.(map[string]string))
	if err != nil {
		return types.NewErr("cannot verify image: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, map[string]any{
		"trusted": response.IsTrusted,
		"digest":  response.Digest,
	})
}
