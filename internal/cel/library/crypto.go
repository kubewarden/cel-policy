package library

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/crypto"
)

// Crypto returns a cel.EnvOption to configure namespaced crypto host-callback
// Kubewarden functions.
//
// # Crypto.VerifyCert
//
// This CEL function accepts a certificate, a certificate chain, and an
// expiration date.
// It returns a bool on whether the provided CertificateVerificationRequest
// (containing a cert to be verified, a cert chain, and an expiration date)
// passes certificate verification.
//
// Accepts 3 arguments:
//   - string,  of PEM-encoded certificate to verify.
//   - list of strings, of PEM-encoded certs, ordered by trust usage
//     (intermediates first, root last). If empty, certificate is assumed trusted.
//   - string in RFC 3339 time format, to check expiration against.
//     If empty, certificate is assumed never expired.
//
// Returns a map(<string>) with 2 fields:
//   - "Trusted": <bool> informing if certificate passed verification or not
//   - "Reason": <string> with reason, in case "Trusted" is false
//
// Usage in CEL:
//
//	crypto.verifyCert(<string>, list(<string>), <string>) -> map(<string>, value)
//
// Example:
//
//	  kw.crypto.verifyCert(
//				 '---BEGIN CERTIFICATE---foo---END CERTIFICATE---',
//		    [
//		      '---BEGIN CERTIFICATE---bar---END CERTIFICATE---'
//		    ],
//		    '2030-08-15T16:23:42+00:00'
//		 )"
func Crypto() cel.EnvOption {
	return cel.Lib(cryptoLib{})
}

type cryptoLib struct{}

// LibraryName implements the SingletonLibrary interface method.
func (cryptoLib) LibraryName() string {
	return "kw.crypto"
}

// CompileOptions implements the Library interface method.
func (cryptoLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// group every binding under a container to simplify usage
		cel.Container("crypto"),

		cel.Function("kw.crypto.verifyCert",
			cel.Overload("kw_crypto_verify_cert",
				[]*cel.Type{
					cel.StringType,
					cel.ListType(cel.StringType),
					cel.StringType,
				},
				cel.MapType(cel.StringType, cel.DynType),
				cel.FunctionBinding(verifyCert),
			),
		),
	}
}

// ProgramOptions implements the Library interface method.
func (cryptoLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func verifyCert(args ...ref.Val) ref.Val {
	cert, ok1 := args[0].Value().(string)
	if !ok1 {
		return types.MaybeNoSuchOverloadErr(args[0])
	}

	certChain, ok2 := args[1].(traits.Lister)
	if !ok2 {
		return types.MaybeNoSuchOverloadErr(args[1])
	}

	notAfter, ok3 := args[2].Value().(string)
	if !ok3 {
		return types.MaybeNoSuchOverloadErr(args[2])
	}

	// convert all cert.Data from string to []rune
	cryptoCert := crypto.Certificate{
		Encoding: crypto.Pem,
		Data:     []rune(cert),
	}
	certChainLength, ok := certChain.Size().(types.Int)
	if !ok {
		return types.NewErr("cannot convert certChain length to int")
	}
	cryptoCertChain := make([]crypto.Certificate, 0, certChainLength)
	for i := types.Int(0); i < certChainLength; i++ {
		certElem, err := certChain.Get(i).ConvertToNative(reflect.TypeOf(""))
		if err != nil {
			return types.NewErr("cannot convert certChain: %s", err)
		}
		certString, ok := certElem.(string)
		if !ok {
			return types.NewErr("cannot convert cert into string")
		}

		cryptoCertChain = append(cryptoCertChain,
			crypto.Certificate{
				Encoding: crypto.Pem,
				Data:     []rune(certString),
			},
		)
	}

	response, err := crypto.VerifyCert(&host, cryptoCert, cryptoCertChain, notAfter)
	if err != nil {
		return types.NewErr("cannot verify certificate: %s", err)
	}

	return types.NewStringInterfaceMap(types.DefaultTypeAdapter,
		map[string]any{
			"Trusted": response.Trusted,
			"Reason":  response.Reason,
		})
}
