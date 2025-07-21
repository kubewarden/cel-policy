//nolint:lll,govet // This file contains long lines and splitting them would not make the code more readable. Also, we shadow the err variable in some places, but it's not a problem.
package settings

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/hashicorp/go-multierror"
	"github.com/kubewarden/cel-policy/internal/cel"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	"k8s.io/kubernetes/pkg/apis/admissionregistration"
)

const (
	StatusReasonUnauthorized          = "Unauthorized"
	StatusReasonForbidden             = "Forbidden"
	StatusReasonInvalid               = "Invalid"
	StatusReasonRequestEntityTooLarge = "RequestEntityTooLarge"
)

//nolint:gochecknoglobals // []string cannot be const
var supportedValidationPolicyReason = []string{
	StatusReasonUnauthorized,
	StatusReasonForbidden,
	StatusReasonInvalid,
	StatusReasonRequestEntityTooLarge,
}

// Settings defines the settings of the policy.
type Settings struct {
	Variables   []Variable   `json:"variables"`
	Validations []Validation `json:"validations"`
	/// FailurePolicy defines how the policy will response to  runtime errors and
	//invalid or mis-configured policy definitions
	FailurePolicy admissionregistration.FailurePolicyType `json:"failurePolicy,omitempty"`
	ParamKind     *admissionregistration.ParamKind        `json:"paramKind,omitempty"`
	ParamRef      *admissionregistration.ParamRef         `json:"paramRef,omitempty"`
}

type Variable struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
}

type Validation struct {
	Expression        string `json:"expression"`
	Message           string `json:"message"`
	MessageExpression string `json:"messageExpression"`
	Reason            string `json:"reason"`
}

// Write a custom unmarshaller to set default values for FailurePolicy to replicate
// Kubernetes behavior
func (s *Settings) UnmarshalJSON(data []byte) error {
	type Alias Settings
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if s.FailurePolicy == "" {
		s.FailurePolicy = admissionregistration.Fail
	}

	return nil
}

func (v *Validation) UnmarshalJSON(data []byte) error {
	type Alias Validation
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(v),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(v.Reason) == 0 {
		v.Reason = StatusReasonInvalid
	}

	return nil
}

// ValidateSettings validates the settings of the policy
// the validation logic is adapted from:
// https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/admissionregistration/validation/validation.go
func ValidateSettings(input []byte) ([]byte, error) {
	settings := Settings{}

	if err := json.Unmarshal(input, &settings); err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("cannot unmarshal settings: %v", err)))
	}

	var result *multierror.Error

	if err := validateParams(settings); err != nil {
		result = multierror.Append(result, fmt.Errorf("failed to validate params: %w", err))
	}

	if len(settings.Validations) == 0 {
		err := newRequiredValueError("validations", "validations must contain at least one item")
		result = multierror.Append(result, err)
	}

	if settings.FailurePolicy != admissionregistration.Ignore && settings.FailurePolicy != admissionregistration.Fail {
		err := newRequiredValueError("failurePolicy", "failurePolicy must be either 'Ignore' or 'Fail'")
		result = multierror.Append(result, err)
	}

	compiler, err := cel.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	for index, variable := range settings.Variables {
		variableType, err := validateVariable(compiler, index, variable)
		if err != nil {
			result = multierror.Append(result, err)
			continue
		}

		if err := compiler.AddVariable(variable.Name, variableType); err != nil {
			return nil, fmt.Errorf("failed to extend CEL env: %w", err)
		}
	}

	if settings.ParamKind != nil && settings.ParamRef != nil {
		if err := compiler.AddVariable("params", types.DynType); err != nil {
			return nil, fmt.Errorf("failed to extend CEL env: %w", err)
		}
	}

	for index, validation := range settings.Validations {
		if err := validateValidations(compiler, index, validation); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if result != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("The settings are invalid: %s", result)))
	}

	return kubewarden.AcceptSettings()
}

func validateParams(settings Settings) error {
	// no params, no validation needed
	if settings.ParamKind == nil && settings.ParamRef == nil {
		return nil
	}
	if settings.ParamKind != nil && (settings.ParamKind.APIVersion == "" || settings.ParamKind.Kind == "") {
		return newRequiredValueError("paramKind", "paramKind must have both APIVersion and Kind specified")
	}
	if settings.ParamRef != nil && (settings.ParamRef.Name == "" && settings.ParamRef.Selector == nil) {
		return newRequiredValueError("paramRef", "paramRef must have either Name or Selector specified")
	}
	if settings.ParamRef != nil && (settings.ParamRef.Name != "" && settings.ParamRef.Selector != nil) {
		return newInvalidValueError("paramRef", settings.ParamRef.Name, "paramRef cannot have both Name and Selector specified")
	}
	if isParameterNotFoundActionInvalid(settings.ParamRef) {
		parameterNotFoundAction := "nil"
		if settings.ParamRef.ParameterNotFoundAction != nil {
			parameterNotFoundAction = string(*settings.ParamRef.ParameterNotFoundAction)
		}
		return newInvalidValueError("paramRef", parameterNotFoundAction, "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified")
	}
	return nil
}

func isParameterNotFoundActionInvalid(paramRef *admissionregistration.ParamRef) bool {
	if paramRef == nil {
		return false
	}
	return paramRef.ParameterNotFoundAction == nil ||
		(paramRef.ParameterNotFoundAction != nil &&
			*paramRef.ParameterNotFoundAction != admissionregistration.AllowAction &&
			*paramRef.ParameterNotFoundAction != admissionregistration.DenyAction)
}

func validateVariable(compiler *cel.Compiler, index int, variable Variable) (*types.Type, error) {
	var result error

	name := strings.TrimSpace(variable.Name)
	if len(name) == 0 {
		err := newRequiredValueError(fmt.Sprintf("variables[%d].name", index), "name is not specified")
		result = multierror.Append(result, err)
	} else if !cel.IsCELIdentifier(variable.Name) {
		err := newInvalidValueError(fmt.Sprintf("variables[%d].name", index), variable.Name, "name is not a valid CEL identifier")
		result = multierror.Append(result, err)
	} else if name == "params" {
		err := newInvalidValueError(fmt.Sprintf("variables[%d].name", index), variable.Name, "'params' name is not allowed. It can conflicts with the 'params' from the policy paramaters configuration")
		result = multierror.Append(result, err)

	}

	var variableType *types.Type

	if len(variable.Expression) == 0 || strings.TrimSpace(variable.Expression) == "" {
		err := newRequiredValueError(fmt.Sprintf("variables[%d].expression", index), "expression is not specified")
		result = multierror.Append(result, err)
	} else {
		ast, err := compiler.CompileCELExpression(variable.Expression)
		if err != nil {
			result = multierror.Append(result, newInvalidValueError(fmt.Sprintf("variables[%d].expression", index), variable.Expression, err.Error()))

			return nil, result
		}
		variableType = ast.OutputType()
	}

	return variableType, result
}

func validateValidations(compiler *cel.Compiler, index int, validation Validation) error {
	var result error

	trimmedExpression := strings.TrimSpace(validation.Expression)
	trimmedMsg := strings.TrimSpace(validation.Message)
	trimmedMessageExpression := strings.TrimSpace(validation.MessageExpression)

	if len(trimmedExpression) == 0 {
		err := newRequiredValueError(fmt.Sprintf("validations[%d].expression", index), "expression is not specified")
		result = multierror.Append(result, err)
	} else {
		if e := compiler.ValidateBoolExpression(validation.Expression); e != nil {
			err := newInvalidValueError(fmt.Sprintf("validations[%d].expression", index), validation.Expression, e.Error())
			result = multierror.Append(result, err)
		}
	}

	if len(validation.MessageExpression) > 0 && len(trimmedMessageExpression) == 0 {
		err := newInvalidValueError(fmt.Sprintf("validations[%d].messageExpression", index), validation.MessageExpression, "must be non-empty if specified")
		result = multierror.Append(result, err)
	} else if len(trimmedMessageExpression) != 0 {
		// use validation.MessageExpression instead of trimmedMessageExpression so that
		// the compiler output shows the correct column.
		if err := compiler.ValidateStringExpression(validation.MessageExpression); err != nil {
			err := newInvalidValueError(fmt.Sprintf("validations[%d].messageExpression", index), validation.MessageExpression, err.Error())
			result = multierror.Append(result, err)
		}
	}
	//nolint:gocritic // Rewriting this code as switch would not make it more readable
	if len(validation.Message) > 0 && len(trimmedMsg) == 0 {
		err := newInvalidValueError(fmt.Sprintf("validations[%d].message", index), validation.Message, "message must be non-empty if specified")
		result = multierror.Append(result, err)
	} else if hasNewlines(trimmedMsg) {
		err := newInvalidValueError(fmt.Sprintf("validations[%d].message", index), validation.Message, "message must not contain line breaks")
		result = multierror.Append(result, err)
	} else if hasNewlines(trimmedMsg) && trimmedMsg == "" {
		err := newRequiredValueError(fmt.Sprintf("validations[%d].message", index), "message must be specified if expression contains line breaks")
		result = multierror.Append(result, err)
	}

	if !slices.Contains(supportedValidationPolicyReason, validation.Reason) {
		err := newNotSupportedValueError(fmt.Sprintf("validations[%d].reason", index), validation.Reason)
		result = multierror.Append(result, err)
	}

	return result
}

func hasNewlines(s string) bool {
	return strings.Contains(s, "\n")
}
