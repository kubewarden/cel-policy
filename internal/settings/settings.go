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
	kubewardenProtocol "github.com/kubewarden/policy-sdk-go/protocol"
)

const (
	StatusReasonUnauthorized          = "Unauthorized"
	StatusReasonForbidden             = "Forbidden"
	StatusReasonInvalid               = "Invalid"
	StatusReasonRequestEntityTooLarge = "RequestEntityTooLarge"
)

var supportedValidationPolicyReason = []string{
	StatusReasonUnauthorized,
	StatusReasonForbidden,
	StatusReasonInvalid,
	StatusReasonRequestEntityTooLarge,
}

// Settings defines the settings of the policy
type Settings struct {
	Variables   []Variable   `json:"variables"`
	Validations []Validation `json:"validations"`
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

func NewSettingsFromValidationReq(validationReq *kubewardenProtocol.ValidationRequest) (Settings, error) {
	settings := Settings{}

	if err := json.Unmarshal(validationReq.Settings, &settings); err != nil {
		return Settings{}, fmt.Errorf("cannot unmarshal settings %w", err)
	}
	return settings, nil
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

	if len(settings.Validations) == 0 {
		err := newRequiredValueError("validations", "validations must contain at least one item")
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

func validateVariable(compiler *cel.Compiler, index int, variable Variable) (*types.Type, error) {
	var result error

	if len(variable.Name) == 0 || strings.TrimSpace(variable.Name) == "" {
		err := newRequiredValueError(fmt.Sprintf("variables[%d].name", index), "name is not specified")
		result = multierror.Append(result, err)
	} else if !cel.IsCELIdentifier(variable.Name) {
		err := newInvalidValueError(fmt.Sprintf("variables[%d].name", index), variable.Name, "name is not a valid CEL identifier")
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

	//nolint:gocritic
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
