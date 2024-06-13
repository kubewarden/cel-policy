//nolint:varnamelen
package library

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	cryptoCap "github.com/kubewarden/policy-sdk-go/pkg/capabilities/crypto"
)

// Crypto provides a CEL function library extension for verifying certificates.
//
// certificate
//
// Returns a certificate verifier that can be used to verify the trust of the certificate.
//
//	kw.crypto.certificate(<string>) <CryptoVerifier>
//
// Examples:
//
//	kw.crypto.certificate('PEM CERTIFICATE') // returns a certificate verifier for the given PEM encoded certificate
//
// certificateChain
//
// Adds a certificate to the certificate chain.
//
//	<CryptoVerifier>.certificateChain(<string>) <CryptoVerifier>
//
// Examples:
//
//	kw.crypto.certificate('PEM CERTIFICATE').certificateChain('PEM CERTIFICATE') // returns a certificate verifier with the given PEM encoded certificate added to the chain
//
// notAfter
//
// Sets the not after date for the certificate verification. If `notAfter` is not set, the certificate is assumed to never expire.
// The date must be a `google.protobuf.Timestamp`.
// A `google.protobuf.Timestamp` can be created using the `timestamp` standard definition, by passing a string in RFC 3339 format.
// See: https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions
//
//	<CryptoVerifier>.notAfter(<google.protobuf.Timestamp>)  <CryptoVerifier>
//
// Examples:
//
//	kw.crypto.certificate('cert.pem').notAfter(timestamp('2000-01-01T00:00:00Z')) // returns a certificate verifier with the not after date set to '2000-01-01T00:00:00Z'
//
// verify
//
// Verifies the trust of the certificate.
// Returns a Response type that contains the trust result.
// `isTrusted()` returns a boolean that indicates if the certificate is trusted.
// `reason()` returns a string that contains the reason why the certificate is not trusted (empty if the certificate is trusted).
//
//	<CryptoVerifier>.verify() <Response>
//
// Examples:
//
//	kw.crypto.certificate('PEM CERTIFICATE').certificateChain('PEM CERTIFICATE').notAfter(timestamp('2000-01-01T00:00:00Z')).verify().isTrusted() // returns true if the certificate is trusted
func Crypto() cel.EnvOption {
	return cel.Lib(cryptoLib{})
}

type cryptoLib struct{}

func (cryptoLib) LibraryName() string {
	return "kw.crypto"
}

func (cryptoLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("kw.crypto.certificate",
			cel.Overload("kw_crypto_certifcate",
				[]*cel.Type{cel.StringType},
				cryptoVerifierType,
				cel.UnaryBinding(cryptoCertificate),
			),
		),
		cel.Function("certificateChain",
			cel.MemberOverload("kw_crypto_verifier_certificate_chain",
				[]*cel.Type{cryptoVerifierType, cel.StringType},
				cryptoVerifierType,
				cel.BinaryBinding(cryptoVerifierCertificateChain),
			),
		),
		cel.Function("notAfter",
			cel.MemberOverload("kw_crypto_verifier_not_after",
				[]*cel.Type{cryptoVerifierType, cel.TimestampType},
				cryptoVerifierType,
				cel.BinaryBinding(cryptoVerifierNotAfter),
			),
		),
		cel.Function("verify",
			cel.MemberOverload("kw_crypto_verifier_verify",
				[]*cel.Type{cryptoVerifierType},
				cryptoResponseType,
				cel.UnaryBinding(cryptoVerifierVerify),
			),
		),
		cel.Function("isTrusted",
			cel.MemberOverload("kw_crypto_response_is_trusted",
				[]*cel.Type{cryptoResponseType},
				cel.BoolType,
				cel.UnaryBinding(cryptoResponseIsTrusted),
			),
		),
		cel.Function("reason",
			cel.MemberOverload("kw_crypto_response_reason",
				[]*cel.Type{cryptoResponseType},
				cel.StringType,
				cel.UnaryBinding(cryptoResponseReason),
			),
		),
	}
}

func (cryptoLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func cryptoCertificate(arg ref.Val) ref.Val {
	certifcate, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return cryptoVerifier{
		receiverOnlyObjectVal: receiverOnlyVal(cryptoVerifierType),
		certifcate:            cryptoCap.Certificate{Encoding: cryptoCap.Pem, Data: []rune(certifcate)},
	}
}

func cryptoVerifierCertificateChain(arg1, arg2 ref.Val) ref.Val {
	verifier, ok := arg1.(cryptoVerifier)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	certifcate, ok := arg2.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	verifier.certifcateChain = append(verifier.certifcateChain, cryptoCap.Certificate{Encoding: cryptoCap.Pem, Data: []rune(certifcate)})

	return verifier
}

func cryptoVerifierNotAfter(arg1, arg2 ref.Val) ref.Val {
	verifier, ok := arg1.(cryptoVerifier)

	if !ok {
		return types.MaybeNoSuchOverloadErr(arg1)
	}

	notAfter, ok := arg2.(types.Timestamp)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg2)
	}

	verifier.notAfter = &notAfter.Time

	return verifier
}

func cryptoVerifierVerify(arg ref.Val) ref.Val {
	verifier, ok := arg.(cryptoVerifier)

	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	response, err := cryptoCap.VerifyCert(&host, verifier.certifcate, verifier.certifcateChain, verifier.notAfter.Format(time.RFC3339))
	if err != nil {
		return types.NewErr(err.Error())
	}

	return cryptoResponse{
		receiverOnlyObjectVal: receiverOnlyVal(cryptoResponseType),
		isTrusted:             response.Trusted,
		reason:                response.Reason,
	}
}

func cryptoResponseIsTrusted(arg ref.Val) ref.Val {
	response, ok := arg.(cryptoResponse)

	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.Bool(response.isTrusted)
}

func cryptoResponseReason(arg ref.Val) ref.Val {
	response, ok := arg.(cryptoResponse)

	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.String(response.reason)
}

var cryptoVerifierType = cel.ObjectType("kw.crypto.Verifier")

type cryptoVerifier struct {
	receiverOnlyObjectVal
	certifcate      cryptoCap.Certificate
	certifcateChain []cryptoCap.Certificate
	notAfter        *time.Time
}

var cryptoResponseType = cel.ObjectType("kw.crypto.Response")

// cryptoResponse is the response object returned by the verify function
type cryptoResponse struct {
	receiverOnlyObjectVal
	isTrusted bool
	reason    string
}
