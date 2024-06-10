//nolint:varnamelen
package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
	verify "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci/verify_v2"
)

// Sigstore provides a CEL function library extension for verifying sigstore signatures of an image.
//
// image
//
// Returns a verifier builder object that can be used to build a specific verifier.
//
//	kw.sigstore.image(<string>) <VerifierBuilder>
//
// Examples:
//
//	kw.sigstore.image('image:latest') // returns a verifier builder for the 'image:latest' image
//
// annotation
//
// Adds an annotation to the verifier builder.
//
//	<VerifierBuilder>.annotation(<string>, <string>) <VerifierBuilder>
//
// Examples:
//
//	kw.sigstore.image('image:latest').annotation('foo', 'bar').annotation('baz', 'qux') // returns a verifier builder with the annotations 'foo'='bar' and 'baz'='qux'
//
// pubKey
//
// Builds a verifier that verifies the signature of an image using a set of public keys.
//
//	<VerifierBuilder>.pubKey(<string>) <PubKeysVerifier>
//	<PubKeysVerifier>.pubKey(<string>) <PubKeysVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').pubKey('pubkey1').pubKey('pubkey2') // returns a verifier that verifies the signature of the 'image:latest' image using the public keys 'pubkey1' and 'pubkey2'
//
// keyless
//
// Builds a verifier that verifies the signature of an image using keyless signing.
// The first argument is the issuer and the second argument is the subject.
//
//	<VerifierBuilder>.keyless(<string>, <string>) <KeylessVerifier>
//	<KeylessVerifier>.keyless(<string>, <string>) <KeylessVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').keyless('issuer1', 'subject1').keyless('issuer2', 'subject2') // returns a verifier that verifies the signature of the 'image:latest' image using keyless signing with the keyless info 'issuer1'='subject1' and 'issuer2'='subject2'
//
// keylessPrefix
//
// Builds a verifier that verifies the signature of an image using keyless signing.
// The first argument is the issuer and the second argument is a subject as an URL prefix.
// The provided subject is sanitized to ensure it is a valid URL prefix and to prevent typosquatting.
// The signature is satisfied only if the subject is a prefix of the signature subject.
//
//	<VerifierBuilder>.keylessPrefix(<string>, <string>) <KeylessPrefixVerifier>
//	<KeylessPrefixVerifier>.keylessPrefix(<string>, <string>) <KeylessPrefixVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').keylessPrefix('issuer1', 'https://example.com/').keylessPrefix('issuer2', 'https://example.org/') // returns a verifier that verifies the signature of the 'image:latest' image using keyless signing with the keyless prefix info 'issuer1'='https://example.com/' and 'issuer2'='https://example.org/'
//
// githubAction
//
// Builds a verifier that verifies sigstore signatures of an image using keyless signatures made via Github Actions.
// The first argument is the owner and the second argument is the repo (optional).
//
//	<VerifierBuilder>.githubAction(<string>, <string>) <GitHubActionVerifier>
//	<VerifierBuilder>.githubAction(<string>) <GitHubActionVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').githubAction('owner1', 'repo1') // returns a verifier that verifies sigstore signatures of the 'image:latest' image using keyless signatures made via Github Actions with the owner 'owner1' and the repo 'repo1'
//
// certificate
//
// Builds a verifier that verifies sigstore signatures of an image using a user provided certificate.
// The certificate must be in PEM format.
//
//	<VerifierBuilder>.certificate(<string>) <CertificateVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').certificate('certificate') // returns a verifier that verifies sigstore signatures of the 'image:latest' image using the provided certificate
//
// certificateChain
//
// Adds a certificate to the certificate verifier's chain.
// The certificate must be in PEM format.
//
//	<CertificateVerifier>.certificateChain(<string>) <CertificateVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').certificate('certificate').certificateChain('certificate1').certificateChain('certificate2') // returns a verifier that verifies sigstore signatures of the 'image:latest' image using the provided certificate and the certificate chain 'certificate1' and 'certificate2'
//
// requireRekorBundle
//
// Sets whether the certificate verifier requires a Rekor bundle to be present in the signature.
// Having a Rekor bundle allows further checks to be performed, e.g. ensuring the signature has been produced during the validity time frame of the cert.
// It is recommended to set this to `true`.
//
//	<CertificateVerifier>.requireRekorBundle(<bool>) <CertificateVerifier>
//
// Examples:
//
//	kw.sigstore.image('image:latest').certificate('certificate').requireRekorBundle(true) // returns a verifier that verifies sigstore signatures of the 'image:latest' image using the provided certificate and requires a Rekor bundle to be present in the signature
//
// verify
//
// Verifies the signature of an image using the verifier.
// Returns a Response object with the methods `isTrusted()` and `digest()` to check the trust of the signature and get the digest of the image respectively.
//
//	<PubKeysVerifier>.verify() <Response>
//	<KeylessVerifier>.verify() <Response>
//	<KeylessPrefixVerifier>.verify() <Response>
//	<GitHubActionVerifier>.verify() <Response>
//	<CertificateVerifier>.verify() <Response>
//
// Examples:
//
//	kw.sigstore.image('image:latest').pubKey('pubkey').verify().isTrusted() // returns whether the signature of the 'image:latest' image using the public key 'pubkey' is trusted
//	kw.sigstore.image('image:latest').keyless('issuer', 'subject').verify().digest() // returns the digest of the 'image:latest' image using keyless signing with the keyless info 'issuer'='subject'
//	kw.sigstore.image('image:latest').keylessPrefix('issuer', 'https://example.com/').verify().isTrusted() // returns whether the signature of the 'image:latest' image using keyless signing with the keyless prefix info 'issuer'='https://example.com/' is trusted
//	kw.sigstore.image('image:latest').github('owner', 'repo').verify().digest() // returns the digest of the 'image:latest' image using keyless signatures made via Github Actions with the owner 'owner' and the repo 'repo'
//	kw.sigstore.image('image:latest').certificate('certificate').certificateChain('certificate1').verify().isTrusted() // returns whether the signature of the 'image:latest' image using the provided certificate is trusted
func Sigstore() cel.EnvOption {
	return cel.Lib(&sigstoreLib{})
}

type sigstoreLib struct{}

func (*sigstoreLib) LibraryName() string {
	return "kw.sigstore"
}

func (*sigstoreLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("kw.sigstore.image",
			cel.Overload("kw_sigstore_image",
				[]*cel.Type{cel.StringType},
				sigstoreVerifierBuilderType,
				cel.UnaryBinding(sigstoreImage),
			),
		),
		cel.Function("annotation",
			cel.MemberOverload("kw_sigstore_verifier_builder_annotation",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType, cel.StringType},
				sigstoreVerifierBuilderType,
				cel.FunctionBinding(sigstoreVerifierBuilderAnnotation),
			),
		),
		cel.Function("pubKey",
			cel.MemberOverload("kw_sigstore_verifier_builder_pub_key",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType},
				sigstorePubKeysVerifierType,
				cel.BinaryBinding(sigstoreVerifierBuilderPubKey),
			),
			cel.MemberOverload("kw_sigstore_pub_keys_verifier_pub_key",
				[]*cel.Type{sigstorePubKeysVerifierType, cel.StringType},
				sigstorePubKeysVerifierType,
				cel.BinaryBinding(sigstorePubKeysVerifierPubKey),
			),
		),
		cel.Function("keyless",
			cel.MemberOverload("kw_sigstore_verifier_builder_keyless",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType, cel.StringType},
				sigstoreKeylessVerifierType,
				cel.FunctionBinding(sigstoreVerifierBuilderKeyless),
			),
			cel.MemberOverload("kw_sigstore_keyless_verifier_keyless",
				[]*cel.Type{sigstoreKeylessVerifierType, cel.StringType, cel.StringType},
				sigstoreKeylessVerifierType,
				cel.FunctionBinding(sigstoreKeylessVerifierKeyless),
			),
		),
		cel.Function("keylessPrefix",
			cel.MemberOverload("kw_sigstore_verifier_builder_keyless_prefix",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType, cel.StringType},
				sigstoreKeylessPrefixVerifierType,
				cel.FunctionBinding(sigstoreVerifierBuilderKeylessPrefix),
			),
			cel.MemberOverload("kw_sigstore_keyless_verifier_keyless_prefix",
				[]*cel.Type{sigstoreKeylessPrefixVerifierType, cel.StringType, cel.StringType},
				sigstoreKeylessPrefixVerifierType,
				cel.FunctionBinding(sigstoreKeylessPrefixVerifierKeylessPrefix),
			),
		),
		cel.Function("githubAction",
			cel.MemberOverload("kw_sigstore_verifier_builder_github_action_owner",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType},
				sigstoreGitHubActionVerifierType,
				cel.BinaryBinding(sigstoreVerifierBuilderGitHubActionOwner),
			),
			cel.MemberOverload("kw_sigstore_verifier_builder_github_action_owner_repo",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType, cel.StringType},
				sigstoreGitHubActionVerifierType,
				cel.FunctionBinding(sigstoreVerifierBuilderGitHubActionOwnerRepo),
			),
		),
		cel.Function("certificate",
			cel.MemberOverload("kw_sigstore_verifier_builder_certificate",
				[]*cel.Type{sigstoreVerifierBuilderType, cel.StringType},
				sigstoreCertificateVerifierType,
				cel.BinaryBinding(sigstoreVerifierBuilderCertificate),
			),
		),
		cel.Function("certificateChain",
			cel.MemberOverload("kw_sigstore_certificate_verifier_certificate_chain",
				[]*cel.Type{sigstoreCertificateVerifierType, cel.StringType},
				sigstoreCertificateVerifierType,
				cel.BinaryBinding(sigstoreCertificateVerifierCertificateChain),
			),
		),
		cel.Function("requireRekorBundle",
			cel.MemberOverload("kw_sigstore_certificate_verifier_require_rekor_bundle",
				[]*cel.Type{sigstoreCertificateVerifierType, cel.BoolType},
				sigstoreCertificateVerifierType,
				cel.BinaryBinding(sigstoreCertificateVerifierRequireRekorBundle),
			),
		),
		cel.Function("verify",
			cel.MemberOverload("kw_sigstore_pub_keys_verifier_verify",
				[]*cel.Type{sigstorePubKeysVerifierType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstorePubKeysVerifierVerify),
			),
			cel.MemberOverload("kw_sigstore_keyless_verifier_verify",
				[]*cel.Type{sigstoreKeylessVerifierType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstoreKeylessVerifierVerify),
			),
			cel.MemberOverload("kw_sigstore_keyless_prefix_verifier_verify",
				[]*cel.Type{sigstoreKeylessPrefixVerifierType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstoreKeylessPrefixVerifierVerify),
			),
			cel.MemberOverload("kw_sigstore_github_verifier_verify",
				[]*cel.Type{sigstoreGitHubActionVerifierType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstoreKeylessGitHubActionsVerifierVerify),
			),
			cel.MemberOverload("kw_sigstore_certificate_verifier_verify",
				[]*cel.Type{sigstoreCertificateVerifierType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstoreCertificateVerifierVerify),
			),
		),
		cel.Function("isTrusted",
			cel.MemberOverload("kw_sigstore_response_is_trusted",
				[]*cel.Type{sigstoreResponseType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstoreResponseIsTrusted),
			),
		),
		cel.Function("digest",
			cel.MemberOverload("kw_sigstore_response_digest",
				[]*cel.Type{sigstoreResponseType},
				sigstoreResponseType,
				cel.UnaryBinding(sigstoreResponseDigest),
			),
		),
	}
}

func (*sigstoreLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func sigstoreImage(arg ref.Val) ref.Val {
	image, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return sigstoreVerifierBuilder{receiverOnlyObjectVal: receiverOnlyVal(sigstoreVerifierBuilderType), image: image}
}

func sigstoreVerifierBuilderAnnotation(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NoSuchOverloadErr()
	}

	builder, ok := args[0].(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	key, ok := args[1].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	value, ok := args[2].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	if builder.annotations == nil {
		builder.annotations = make(map[string]string)
	}

	builder.annotations[key] = value

	return builder
}

func sigstoreVerifierBuilderPubKey(arg1, arg2 ref.Val) ref.Val {
	builder, ok := arg1.(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	pubKey, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	return sigstorePubKeysVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(sigstorePubKeysVerifierType),
		image:                 builder.image,
		annotations:           builder.annotations,
		pubKeys:               []string{pubKey},
	}
}

func sigstorePubKeysVerifierPubKey(arg1, arg2 ref.Val) ref.Val {
	verifier, ok := arg1.(sigstorePubKeysVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	pubKey, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	verifier.pubKeys = append(verifier.pubKeys, pubKey)

	return verifier
}

func sigstorePubKeysVerifierVerify(arg ref.Val) ref.Val {
	verifier, ok := arg.(sigstorePubKeysVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return verifier.verify()
}

func sigstoreVerifierBuilderKeyless(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NoSuchOverloadErr()
	}

	builder, ok := args[0].(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	issuer, ok := args[1].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	subject, ok := args[2].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	keyless := []oci.KeylessInfo{{Issuer: issuer, Subject: subject}}

	return sigstoreKeylessVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreKeylessVerifierType),
		image:                 builder.image,
		annotations:           builder.annotations,
		keyless:               keyless,
	}
}

func sigstoreKeylessVerifierKeyless(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NoSuchOverloadErr()
	}

	verifier, ok := args[0].(sigstoreKeylessVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	issuer, ok := args[1].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	subject, ok := args[2].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	verifier.keyless = append(verifier.keyless, oci.KeylessInfo{Issuer: issuer, Subject: subject})

	return verifier
}

func sigstoreKeylessVerifierVerify(arg ref.Val) ref.Val {
	verifier, ok := arg.(sigstoreKeylessVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return verifier.verify()
}

func sigstoreVerifierBuilderKeylessPrefix(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NoSuchOverloadErr()
	}

	builder, ok := args[0].(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	issuer, ok := args[1].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	urlPrefix, ok := args[2].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	keylessPrefix := []verify.KeylessPrefixInfo{{Issuer: issuer, UrlPrefix: urlPrefix}}

	return sigstoreKeylessPrefixVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreKeylessPrefixVerifierType),
		image:                 builder.image,
		annotations:           builder.annotations,
		keylessPrefix:         keylessPrefix,
	}
}

func sigstoreKeylessPrefixVerifierKeylessPrefix(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NoSuchOverloadErr()
	}

	verifier, ok := args[0].(sigstoreKeylessPrefixVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	issuer, ok := args[1].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	urlPrefix, ok := args[2].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	verifier.keylessPrefix = append(verifier.keylessPrefix, verify.KeylessPrefixInfo{Issuer: issuer, UrlPrefix: urlPrefix})

	return verifier
}

func sigstoreKeylessPrefixVerifierVerify(arg ref.Val) ref.Val {
	verifier, ok := arg.(sigstoreKeylessPrefixVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return verifier.verify()
}

func sigstoreVerifierBuilderGitHubActionOwner(arg1, arg2 ref.Val) ref.Val {
	builder, ok := arg1.(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	owner, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	return sigstoreGitHubActionVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreGitHubActionVerifierType),
		image:                 builder.image,
		annotations:           builder.annotations,
		owner:                 owner,
	}
}

func sigstoreVerifierBuilderGitHubActionOwnerRepo(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NoSuchOverloadErr()
	}

	builder, ok := args[0].(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	owner, ok := args[1].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	repo, ok := args[2].Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	return sigstoreGitHubActionVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreGitHubActionVerifierType),
		image:                 builder.image,
		annotations:           builder.annotations,
		owner:                 owner,
		repo:                  repo,
	}
}

func sigstoreKeylessGitHubActionsVerifierVerify(arg ref.Val) ref.Val {
	verifier, ok := arg.(sigstoreGitHubActionVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return verifier.verify()
}

func sigstoreVerifierBuilderCertificate(arg1, arg2 ref.Val) ref.Val {
	builder, ok := arg1.(sigstoreVerifierBuilder)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	certificate, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	return sigstoreCertificateVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreCertificateVerifierType),
		image:                 builder.image,
		annotations:           builder.annotations,
		certificate:           []rune(certificate),
	}
}

func sigstoreCertificateVerifierCertificateChain(arg1, arg2 ref.Val) ref.Val {
	verifier, ok := arg1.(sigstoreCertificateVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	certificate, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	verifier.certificateChain = append(verifier.certificateChain, []rune(certificate))

	return verifier
}

func sigstoreCertificateVerifierRequireRekorBundle(arg1, arg2 ref.Val) ref.Val {
	verifier, ok := arg1.(sigstoreCertificateVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	requireRekorBundle, ok := arg2.Value().(bool)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	verifier.requireRekorBundle = requireRekorBundle

	return verifier
}

func sigstoreCertificateVerifierVerify(arg ref.Val) ref.Val {
	verifier, ok := arg.(sigstoreCertificateVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return verifier.verify()
}

func sigstoreResponseIsTrusted(arg ref.Val) ref.Val {
	response, ok := arg.(sigstoreResponse)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.Bool(response.isTrusted)
}

func sigstoreResponseDigest(arg ref.Val) ref.Val {
	response, ok := arg.(sigstoreResponse)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.String(response.digest)
}

var sigstoreVerifierBuilderType = cel.ObjectType("kw.sigstore.VerifierBuilder")

// sigstoreVerifierBuilder is an intermediate object is used to build a specific verifier
type sigstoreVerifierBuilder struct {
	receiverOnlyObjectVal
	image       string
	annotations map[string]string
}

var sigstorePubKeysVerifierType = cel.ObjectType("kw.sigstore.PubKeysVerifier")

// sigstorePubKeysVerifier verifies the signature of an image using a set of public keys
type sigstorePubKeysVerifier struct {
	receiverOnlyObjectVal
	image       string
	annotations map[string]string
	pubKeys     []string
}

func (v *sigstorePubKeysVerifier) verify() ref.Val {
	response, err := verify.VerifyPubKeysImage(&host, v.image, v.pubKeys, v.annotations)
	if err != nil {
		return types.NewErr("failed to verify image: %s", err)
	}

	return sigstoreResponse{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreResponseType),
		isTrusted:             response.IsTrusted,
		digest:                response.Digest,
	}
}

var sigstoreKeylessVerifierType = cel.ObjectType("kw.sigstore.KeylessVerifier")

// sigstoreKeylessVerifier verifies the signature of an image using keyless signing
type sigstoreKeylessVerifier struct {
	receiverOnlyObjectVal
	image       string
	annotations map[string]string
	keyless     []oci.KeylessInfo
}

func (v *sigstoreKeylessVerifier) verify() ref.Val {
	response, err := verify.VerifyKeylessExactMatch(&host, v.image, v.keyless, v.annotations)
	if err != nil {
		return types.NewErr("failed to verify image: %s", err)
	}

	return sigstoreResponse{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreResponseType),
		isTrusted:             response.IsTrusted,
		digest:                response.Digest,
	}
}

var sigstoreKeylessPrefixVerifierType = cel.ObjectType("kw.sigstore.KeylessPrefixVerifier")

// sigstoreKeylessPrefixVerifier verifies the signature of an image using keyless signing
type sigstoreKeylessPrefixVerifier struct {
	receiverOnlyObjectVal
	image         string
	annotations   map[string]string
	keylessPrefix []verify.KeylessPrefixInfo
}

func (v *sigstoreKeylessPrefixVerifier) verify() ref.Val {
	response, err := verify.VerifyKeylessPrefixMatch(&host, v.image, v.keylessPrefix, v.annotations)
	if err != nil {
		return types.NewErr("failed to verify image: %s", err)
	}

	return sigstoreResponse{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreResponseType),
		isTrusted:             response.IsTrusted,
		digest:                response.Digest,
	}
}

var sigstoreGitHubActionVerifierType = cel.ObjectType("kw.sigstore.GitHubActionVerifier")

// sigstoreGitHubActionVerifier verifies sigstore signatures of an image using keyless signatures made via Github Actions
type sigstoreGitHubActionVerifier struct {
	receiverOnlyObjectVal
	image       string
	annotations map[string]string
	owner       string
	repo        string
}

func (v *sigstoreGitHubActionVerifier) verify() ref.Val {
	response, err := verify.VerifyKeylessGithubActions(&host, v.image, v.owner, v.repo, v.annotations)
	if err != nil {
		return types.NewErr("failed to verify image: %s", err)
	}

	return sigstoreResponse{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreResponseType),
		isTrusted:             response.IsTrusted,
		digest:                response.Digest,
	}
}

var sigstoreCertificateVerifierType = cel.ObjectType("kw.sigstore.CertificateVerifier")

// sigstoreCertificateVerifier verifies sigstore signatures of an image using a user provided certificate\
type sigstoreCertificateVerifier struct {
	receiverOnlyObjectVal
	image              string
	annotations        map[string]string
	certificate        []rune
	certificateChain   [][]rune
	requireRekorBundle bool
}

func (v *sigstoreCertificateVerifier) verify() ref.Val {
	response, err := verify.VerifyCertificate(&host, v.image, v.certificate, v.certificateChain, v.requireRekorBundle, v.annotations)
	if err != nil {
		return types.NewErr("failed to verify image: %s", err)
	}

	return sigstoreResponse{
		receiverOnlyObjectVal: receiverOnlyVal(sigstoreResponseType),
		isTrusted:             response.IsTrusted,
		digest:                response.Digest,
	}
}

var sigstoreResponseType = cel.ObjectType("kw.sigstore.Response")

// sigstoreResponse is the response object returned by the verify function
type sigstoreResponse struct {
	receiverOnlyObjectVal
	isTrusted bool
	digest    string
}
