package library

import (
	"encoding/json"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	manifestDigestCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/manifest_digest"
)

// OCI provides a CEL function library extension for retrieving the manifest of a given image.
//
// image
//
// Returns an OCI client object that can be used to retrieve the manifest of the provided image.
//
//	kw.oci.image(<string>) <OCIClient>
//
// Examples:
//
//	kw.oci.image('image:latest') // returns an OCIClient for the 'image:latest' image
//
// manifest
//
// Returns the manifest of the image.
// The returned value, depends of the given image. It could be a OCI image manifest
// or a OCI index image manifest. See more at:
// https://github.com/opencontainers/image-spec/blob/main/manifest.md
// https://github.com/opencontainers/image-spec/blob/main/image-index.md
// If the response is an OCI index image manifest, the image field will be nil.
// If the response is an OCI image manifest, the index field will be nil.
//
//	<OCIClient>.manifest() <DynamicMap>
//
// Examples:
//
//	kw.oci.image('image:latest').manifest().index // returns the index manfest, the image field is nil
//
// or
//
//	kw.oci.image('image:latest').manifest().image // returns the image manifest, the index field is nil
//
// manifestDigest
//
// Returns the digest of the image manifest.
//
//	<OCIClient>.manifestDigest() <string>
//
// Examples:
//
//	kw.oci.image('image:latest').manifestDigest() // returns the digest of the image manifest
//
// manifestConfig
//
// Returns the manifest, digest and image configuration of the OCI image.
// See more information about the fields available of manifest and image
// configuration at:
// https://github.com/opencontainers/image-spec/blob/main/manifest.md
// https://github.com/opencontainers/image-spec/blob/main/config.md
//
//	<OCIClient>.manifestConfig() <DynamicMap>
//
// Examples:
//
//	kw.oci.image('image:latest').manifestConfig().manifest // returns the image manifest
//	kw.oci.image('image:latest').manifestConfig().config // returns the image configuration
//	kw.oci.image('image:latest').manifestConfig().digest // returns the image digest
func OCI() cel.EnvOption {
	return cel.Lib(&ociLib{})
}

type ociLib struct{}

func (*ociLib) LibraryName() string {
	return "kw.oci"
}

func (*ociLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("kw.oci.image",
			cel.Overload("kw_oci_image",
				[]*cel.Type{cel.StringType},
				ociClientType,
				cel.UnaryBinding(ociImage),
			),
		),
		cel.Function("manifest",
			cel.MemberOverload("kw_k8s_manifest",
				[]*cel.Type{ociClientType},
				cel.DynType,
				cel.UnaryBinding(ociClientManifest),
			),
		),
		cel.Function("manifestDigest",
			cel.MemberOverload("kw_k8s_manifest_digest",
				[]*cel.Type{ociClientType},
				cel.StringType,
				cel.UnaryBinding(ociClientManifestDigest),
			),
		),
		cel.Function("manifestConfig",
			cel.MemberOverload("kw_k8s_manifest_config",
				[]*cel.Type{ociClientType},
				cel.DynType,
				cel.UnaryBinding(ociClientManifestConfig),
			),
		),
	}
}

func (*ociLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func ociImage(arg ref.Val) ref.Val {
	image, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return ociClient{
		receiverOnlyObjectVal: receiverOnlyVal(ociClientType),
		image:                 image,
	}
}

func ociClientManifest(arg ref.Val) ref.Val {
	ociClient, ok := arg.(ociClient)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return ociClient.manifest()
}

func ociClientManifestConfig(arg ref.Val) ref.Val {
	ociClient, ok := arg.(ociClient)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return ociClient.manifestConfig()
}

func ociClientManifestDigest(arg ref.Val) ref.Val {
	ociClient, ok := arg.(ociClient)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return ociClient.manifestDigest()
}

var ociClientType = cel.ObjectType("kw.oci.OCIClient")

// ociClient is a the client to interact with OCI-related capabilities.
type ociClient struct {
	receiverOnlyObjectVal
	image string
}

func (c *ociClient) manifest() ref.Val {
	payload, err := json.Marshal(c.image)
	if err != nil {
		return types.NewErr("failed to marshal image name: %s", err)
	}

	// We are using the host.Client.HostCall method to call the host directly as the SDK call
	// returns a struct with external types but we want to return a DynamicMap that maps to the JSON response.
	responsePayload, err := host.Client.HostCall("kubewarden", "oci", "v1/oci_manifest", payload)
	if err != nil {
		return types.NewErr("failed to call host: %s", err)
	}

	var response map[string]interface{}
	err = json.Unmarshal(responsePayload, &response)
	if err != nil {
		return types.NewErr("failed to unmarshal response payload: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}

func (c *ociClient) manifestDigest() ref.Val {
	digest, err := manifestDigestCap.GetOCIManifestDigest(&host, c.image)
	if err != nil {
		return types.NewErr("cannot get oci manifest: %s", err)
	}

	return types.String(digest)
}

func (c *ociClient) manifestConfig() ref.Val {
	payload, err := json.Marshal(c.image)
	if err != nil {
		return types.NewErr("failed to marshal image name: %s", err)
	}

	// We are using the host.Client.HostCall method to call the host directly as the SDK call
	// returns a struct with external types but we want to return a DynamicMap that maps to the JSON response.
	responsePayload, err := host.Client.HostCall("kubewarden", "oci", "v1/oci_manifest_config", payload)
	if err != nil {
		return types.NewErr("failed to call host: %s", err)
	}

	var response map[string]interface{}
	err = json.Unmarshal(responsePayload, &response)
	if err != nil {
		return types.NewErr("failed to unmarshal response payload: %s", err)
	}

	return types.NewDynamicMap(types.DefaultTypeAdapter, response)
}
