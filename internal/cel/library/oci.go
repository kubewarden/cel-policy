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
//
// # OCI.VerifyKeylessPrefixMatch
//
// Verify sigstore signatures of an image using keyless. Here, the provided
// subject string is treated as a URL prefix, and sanitized to a valid URL on
// itself by appending `/` to prevent typosquatting. Then, the provided subject
// will satisfy the signature only if it is a prefix of the signature subject.
// Usage in CEL:
//	OCI.VerifyKeylessPrefixMatch(<string>, <list(oci.KeylessPrefixInfo{Issuer: <string>, UrlPrefix: <string>})>, map(<string>)<string>) -> <bool, string>
//
// Arguments:
// * `image` - image to be verified
// * `keyless` - list of issuers and subjects
// * `annotations` - annotations that must have been provided by all signers when they signed the OCI artifact
//
// # OCI.VerifyCertificate
//
// Verify sigstore signatures of an image using a user provided certificate
// Usage in CEL:
//	OCI.VerifyCertificate(<string>, <string>, <list(<string>)>, <bool>, map(<string>)<string>) -> <bool, string>
//
// Arguments:
// *  `image` - image to be verified
// *  `certificate` - PEM encoded certificate used to verify the signature
// *  `certificate_chain` - Optional. PEM encoded certificates used to verify
//    `certificate`. When not specified, the certificate is assumed to be trusted
// *  `require_rekor_bundle` - require the signature layer to have a Rekor bundle.
//    Having a Rekor bundle allows further checks to be performed, like ensuring
//    the signature has been produced during the validity time frame of the
//    certificate. It is recommended to set this value to `true` to have a more
//    secure verification process.
// *  `annotations` - annotations that must have been provided by all signers when
//    they signed the OCI artifact

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
		ext.NativeTypes(reflect.TypeOf(&verifyV2.KeylessPrefixInfo{})),

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

		cel.Function("kw.oci.verifyKeylessPrefixMatch",
			cel.Overload("kw_oci_verify_keyless_prefix_match",
				[]*cel.Type{
					cel.StringType,
					cel.ListType(cel.ObjectType("verify_v2.KeylessPrefixInfo")),
					cel.MapType(cel.StringType, cel.StringType),
				},
				cel.DynType,
				cel.FunctionBinding(verifyKeylessPrefixMatch),
			),
		),

		cel.Function("kw.oci.verifyCertificate",
			cel.Overload("kw_oci_verify_certificate",
				[]*cel.Type{
					cel.StringType,
					cel.StringType,
					cel.ListType(cel.StringType),
					cel.BoolType,
					cel.MapType(cel.StringType, cel.StringType),
				},
				cel.DynType,
				cel.FunctionBinding(verifyCertificate),
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

func verifyKeylessPrefixMatch(args ...ref.Val) ref.Val { //nolint: dupl
	image, ok1 := args[0].Value().(string)
	if !ok1 {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	keylessPrefix, ok2 := args[1].(traits.Lister)
	if !ok2 {
		return types.MaybeNoSuchOverloadErr(args[1])
	}
	keylessPrefixLength, ok := keylessPrefix.Size().(types.Int)
	if !ok {
		return types.NewErr("cannot convert keyless prefix info length to int")
	}
	keylessPrefixList := make([]verifyV2.KeylessPrefixInfo, 0, keylessPrefixLength)
	for i := types.Int(0); i < keylessPrefixLength; i++ {
		elem, err := keylessPrefix.Get(i).ConvertToNative(reflect.TypeOf(verifyV2.KeylessPrefixInfo{}))
		if err != nil {
			return types.NewErr("cannot convert keyless prefix info: %s", err)
		}
		elemKeylessPrefixInfo, ok := elem.(verifyV2.KeylessPrefixInfo)
		if !ok {
			return types.NewErr("cannot convert keyless prefix info length to int")
		}
		keylessPrefixList = append(keylessPrefixList, elemKeylessPrefixInfo)
	}

	annotations, ok4 := args[2].(traits.Mapper)
	if !ok4 {
		return types.MaybeNoSuchOverloadErr(args[2])
	}
	annotationsMap, err := annotations.ConvertToNative(reflect.TypeOf(map[string]string{}))
	if err != nil {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	response, err := verifyV2.VerifyKeylessPrefixMatch(&host, image, keylessPrefixList, annotationsMap.(map[string]string))
	if err != nil {
		return types.NewErr("cannot verify image: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, map[string]any{
		"trusted": response.IsTrusted,
		"digest":  response.Digest,
	})
}

func verifyCertificate(args ...ref.Val) ref.Val {
	image, ok1 := args[0].Value().(string)
	if !ok1 {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	cert, ok2 := args[1].Value().(string)
	if !ok2 {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	certChain, ok3 := args[2].(traits.Lister)
	if !ok3 {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	requireRekorBundle, ok4 := args[3].Value().(bool)
	if !ok4 {
		return types.MaybeNoSuchOverloadErr(args[3])
	}

	annotations, ok4 := args[4].(traits.Mapper)
	if !ok4 {
		return types.MaybeNoSuchOverloadErr(args[4])
	}
	annotationsMap, err := annotations.ConvertToNative(reflect.TypeOf(map[string]string{}))
	if err != nil {
		return types.MaybeNoSuchOverloadErr(args[4])
	}

	// convert all certChain from list(string) to [][]rune
	certChainLength, ok := certChain.Size().(types.Int)
	if !ok {
		return types.NewErr("cannot convert certChain length to int")
	}
	certChainRune := make([][]rune, 0, certChainLength)
	for i := types.Int(0); i < certChainLength; i++ {
		elem, err2 := certChain.Get(i).ConvertToNative(reflect.TypeOf(""))
		if err2 != nil {
			return types.NewErr("cannot convert certChain: %s", err)
		}
		elemString, ok := elem.(string)
		if !ok {
			return types.NewErr("cannot convert cert into string")
		}
		certChainRune = append(certChainRune, []rune(elemString))
	}

	response, err := verifyV2.VerifyCertificate(&host, image, []rune(cert), certChainRune, requireRekorBundle, annotationsMap.(map[string]string))
	if err != nil {
		return types.NewErr("cannot verify image: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, map[string]any{
		"trusted": response.IsTrusted,
		"digest":  response.Digest,
	})
}
