package validate

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/cel-policy/internal/cel"
	"github.com/kubewarden/cel-policy/internal/settings"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	"github.com/kubewarden/policy-sdk-go/protocol"
	"k8s.io/kubernetes/pkg/apis/admissionregistration"
)

func handleFailureInParamsRetrieval(validationRequest ValidationRequest, errorMessage string) ([]byte, error) {
	// Kubernetes just accept the request when parameterNotFoundAction is Allow.
	// https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#paramref
	if *validationRequest.Settings.ParamRef.ParameterNotFoundAction == admissionregistration.AllowAction ||
		validationRequest.Settings.FailurePolicy == admissionregistration.Ignore {
		return kubewarden.AcceptRequest()
	}
	message := kubewarden.Message(fmt.Sprintf("failed to get params for performing policy evaluation: %s", errorMessage))
	return kubewarden.RejectRequest(message, reasonToStatusCode(settings.StatusReasonInvalid))
}

func hasParamsRefSelector(validationRequest ValidationRequest) bool {
	return validationRequest.Settings.ParamRef != nil && validationRequest.Settings.ParamRef.Selector != nil
}

func hasParamsNameSelector(validationRequest ValidationRequest) bool {
	return validationRequest.Settings.ParamRef != nil && validationRequest.Settings.ParamRef.Name != ""
}

func getEvaluationParams(validationRequest ValidationRequest, requestMap map[string]any) ([]any, error) {
	if hasParamsRefSelector(validationRequest) {
		return getParamsBySelector(validationRequest, requestMap)
	}

	if hasParamsNameSelector(validationRequest) {
		param, err := getParamsByName(validationRequest, requestMap)
		if err != nil {
			return nil, err
		}
		return []any{param}, nil
	}
	return []any{}, nil
}

// Function used to get the namespace, apiVersion and kind of the resource to fetch
// the parameters from. If the ParamRef.Namespace is not set, the namespace of the
// request being validated is used.
//
// This is the same behavior as in ValidatingAdmissionPolicy
// https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#per-namespace-parameters
func getResourceInfo(validationRequest ValidationRequest, requestMap map[string]any) (string, string, string) {
	namespace := validationRequest.Settings.ParamRef.Namespace
	if namespace == "" {
		namespace, _ = requestMap["namespace"].(string)
	}
	apiVersion := validationRequest.Settings.ParamKind.APIVersion
	kind := validationRequest.Settings.ParamKind.Kind
	return namespace, apiVersion, kind
}

func getParamsByName(validationRequest ValidationRequest, requestMap map[string]any) (any, error) {
	name := validationRequest.Settings.ParamRef.Name
	namespace, apiVersion, kind := getResourceInfo(validationRequest, requestMap)
	return getKubernetesResource(name, namespace, apiVersion, kind)
}

func getParamsBySelector(validationRequest ValidationRequest, requestMap map[string]any) ([]any, error) {
	namespace, apiVersion, kind := getResourceInfo(validationRequest, requestMap)
	params, err := getKubernetesResourceList(namespace, apiVersion, kind, validationRequest.Settings.ParamRef.Selector)
	if err != nil {
		return nil, err
	}
	if len(params) == 0 {
		return nil, errors.New("no parameters found")
	}
	return params, nil
}

func evalValidationsAgainstParamsList(
	compiler *cel.Compiler,
	vars map[string]any,
	paramsList []any,
	validations []settings.Validation,
) (*protocol.ValidationResponse, error) {
	for _, params := range paramsList {
		vars["params"] = func() ref.Val {
			return types.NewDynamicMap(types.DefaultTypeAdapter, params)
		}

		response, err := evalValidations(compiler, vars, validations)
		if err != nil {
			return nil, err
		}
		if !response.Accepted {
			return response, nil
		}
	}
	return buildAcceptResponse(), nil
}
