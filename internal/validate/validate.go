//nolint:lll,govet // This file contains long lines and splitting them would not make the code more readable.Also, we shadow the err variable in some places, but it's not a problem.
package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubewarden/cel-policy/internal/cel"
	"github.com/kubewarden/cel-policy/internal/settings"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	"github.com/kubewarden/policy-sdk-go/protocol"
)

const (
	httpBadRequestStatusCode     = 400
	httpForbiddenStatusCode      = 403
	httpEntityTooLargeStatusCode = 413
	httpUnauthorizedStatusCode   = 401
)

type ValidationRequest struct {
	Request  json.RawMessage   `json:"request"`
	Settings settings.Settings `json:"settings"`
}

func Validate(payload []byte) ([]byte, error) {
	validationRequest := ValidationRequest{}

	if err := json.Unmarshal(payload, &validationRequest); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(fmt.Sprintf("Error deserializing validation request: %v", err)),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	request := protocol.KubernetesAdmissionRequest{}
	if err := json.Unmarshal(validationRequest.Request, &request); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(fmt.Sprintf("Error deserializing request: %v", err)),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	compiler, err := cel.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL compiler: %w", err)
	}

	object := map[string]interface{}{}
	err = json.Unmarshal(request.Object, &object)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal request object %w", err)
	}

	oldObject := map[string]interface{}{}
	if request.OldObject != nil {
		err = json.Unmarshal(request.OldObject, &oldObject)
		if err != nil {
			return nil, fmt.Errorf("cannot unmarshal request oldObject %w", err)
		}
	}

	requestMap := map[string]interface{}{}
	if err = json.Unmarshal(validationRequest.Request, &requestMap); err != nil {
		return nil, fmt.Errorf("cannot unmarshal request %w", err)
	}

	vars := map[string]interface{}{
		"object":    object,
		"oldObject": oldObject,
		"request":   requestMap,
		"namespaceObject": func() ref.Val {
			// lazy load namespaceObject
			objectMeta, ok := object["metadata"].(map[string]interface{})
			if !ok {
				return types.NullValue
			}

			if objectNamespace, ok := objectMeta["namespace"].(string); ok && objectNamespace != "" {
				return getNamespaceObject(objectNamespace)
			}

			return types.NullValue
		},
	}

	paramsList, err := getEvaluationParams(validationRequest, requestMap)
	if err != nil {
		return handleFailureInParamsRetrieval(validationRequest, err.Error())
	}

	if err = evalVariables(compiler, vars, validationRequest.Settings.Variables); err != nil {
		return nil, fmt.Errorf("failed to evaluate variables: %w", err)
	}

	if len(paramsList) > 0 {
		response, err := evalValidationsAgainstParamsList(
			compiler,
			vars,
			paramsList,
			validationRequest.Settings.Validations)
		if err != nil {
			return nil, err
		}
		return json.Marshal(response)
	}

	response, err := evalValidations(compiler, vars, validationRequest.Settings.Validations)
	if err != nil {
		return nil, err
	}
	return json.Marshal(response)
}

func evalVariables(compiler *cel.Compiler, vars map[string]interface{}, variables []settings.Variable) error {
	for _, variable := range variables {
		ast, err := compiler.CompileCELExpression(variable.Expression)
		if err != nil {
			return err
		}

		if err = compiler.AddVariable(variable.Name, ast.OutputType()); err != nil {
			return err
		}
		// lazy load variables
		vars[fmt.Sprintf("variables.%s", variable.Name)] = func() ref.Val {
			val, err := compiler.EvalCELExpression(vars, ast)
			if err != nil {
				return types.WrapErr(err)
			}

			return val
		}
	}

	return nil
}

func buildAcceptResponse() *protocol.ValidationResponse {
	return &protocol.ValidationResponse{
		Accepted: true,
	}
}

func buildRejectResponse(message kubewarden.Message, code kubewarden.Code) *protocol.ValidationResponse {
	messageStr := string(message)
	codeUint16 := uint16(code)
	return &protocol.ValidationResponse{
		Accepted: false,
		Message:  &messageStr,
		Code:     &codeUint16,
	}
}

func evalValidations(compiler *cel.Compiler, vars map[string]interface{}, validations []settings.Validation) (*protocol.ValidationResponse, error) {
	for _, validation := range validations {
		message, reason, err := evaluateValidation(compiler, vars, validation)
		if err != nil {
			return nil, err
		}

		if message != "" {
			return buildRejectResponse(message, reason), nil
		}
	}
	return buildAcceptResponse(), nil
}

// evaluateValidation evaluates a single validation expression.
// If the expression evaluates to false, it returns a rejection message and code.
// If the expression evaluates to true, it returns empty message and code 0.
func evaluateValidation(compiler *cel.Compiler, vars map[string]any, validation settings.Validation) (kubewarden.Message, kubewarden.Code, error) {
	ast, err := compiler.CompileCELExpression(validation.Expression)
	if err != nil {
		return "", 0, fmt.Errorf("failed to compile expression: %w", err)
	}

	val, err := compiler.EvalCELExpression(vars, ast)
	if err != nil {
		return "", 0, fmt.Errorf("failed to evaluate expression: %w", err)
	}

	if val == types.False {
		reason := reasonToStatusCode(validation.Reason)

		if validation.MessageExpression != "" {
			message, err := evalMessageExpression(compiler, vars, validation.MessageExpression)
			if err != nil {
				return "", 0, fmt.Errorf("failed to evaluate message expression: %w", err)
			}
			return kubewarden.Message(message), reason, nil
		}
		if validation.Message != "" {
			return kubewarden.Message(validation.Message), reason, nil
		}

		return kubewarden.Message(fmt.Sprintf("failed expression: %s", strings.TrimSpace(validation.Expression))), reason, nil
	}

	return "", 0, nil
}

func evalMessageExpression(compiler *cel.Compiler, vars map[string]interface{}, messageExpression string) (string, error) {
	ast, err := compiler.CompileCELExpression(messageExpression)
	if err != nil {
		return "", err
	}

	val, err := compiler.EvalCELExpression(vars, ast)
	if err != nil {
		return "", err
	}

	message, ok := val.Value().(string)
	if !ok {
		return "", errors.New("message expression must evaluate to string")
	}

	return message, nil
}

func reasonToStatusCode(reason string) kubewarden.Code {
	var statusCode kubewarden.Code
	switch reason {
	case settings.StatusReasonInvalid:
		statusCode = kubewarden.Code(httpBadRequestStatusCode)
	case settings.StatusReasonForbidden:
		statusCode = httpForbiddenStatusCode
	case settings.StatusReasonRequestEntityTooLarge:
		statusCode = httpEntityTooLargeStatusCode
	case settings.StatusReasonUnauthorized:
		statusCode = httpUnauthorizedStatusCode
	default:
		// This should never happen since we validate the settings when loading the policy
		log.Fatalf("unknown reason: %v", reason)
	}

	return statusCode
}
