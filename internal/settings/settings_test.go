package settings

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/kubernetes/pkg/apis/admissionregistration"
)

// TestValidateSettings unit tests adapted from:
// https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/admissionregistration/validation/validation_test.go
func TestValidateSettings(t *testing.T) {
	tests := []struct {
		name          string
		settings      Settings
		expectedError string
	}{
		{
			name: "Validations is required",
			settings: Settings{
				Validations: []Validation{},
			},

			expectedError: `validations: Required value: validations must contain at least one item`,
		},
		{
			name: "Invalid Validations Reason",
			settings: Settings{
				Validations: []Validation{
					{
						Expression: "object.x < 100",
						Reason:     "other",
					},
				},
			},
			expectedError: `validations[0].reason: Unsupported value: "other"`,
		},
		{
			name: "expression is required",
			settings: Settings{
				Validations: []Validation{{}},
			},
			expectedError: `validations[0].expression: Required value: expression is not specified`,
		},
		{
			name: "invalid expression",
			settings: Settings{
				Validations: []Validation{{Expression: "object.x in [1, 2, "}},
			},
			expectedError: `validations[0].expression: Invalid value: "object.x in [1, 2, ": compilation failed: ERROR: <input>:1:20: Syntax error: missing ']' at '<EOF>`,
		},
		{
			name: "messageExpression of wrong type",
			settings: Settings{
				Validations: []Validation{{Expression: "true", MessageExpression: "0 == 0"}},
			},
			expectedError: `validations[0].messageExpression: Invalid value: "0 == 0": must evaluate to string`,
		},
		{
			name: "variable composition empty name",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "    ",
						Expression: "true",
					},
				},
				Validations: []Validation{
					{
						Expression: "true",
					},
				},
			},
			expectedError: `variables[0].name: Required value: name is not specified`,
		},
		{
			name: "variable name cannot be 'params'",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "params",
						Expression: "true",
					},
				},
				Validations: []Validation{
					{
						Expression: "true",
					},
				},
			},
			expectedError: `'params' name is not allowed. It can conflicts with the 'params' from the policy paramaters configuration`,
		},
		{
			name: "variable composition name is not a valid identifier",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "4ever",
						Expression: "true",
					},
				},
				Validations: []Validation{
					{
						Expression: "true",
					},
				},
			},
			expectedError: `variables[0].name: Invalid value: "4ever": name is not a valid CEL identifier`,
		},
		{
			name: "variable composition cannot compile",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "foo",
						Expression: "114 + '514'", // compile error: type confusion
					},
				},
				Validations: []Validation{
					{
						Expression: "true",
					},
				},
			},
			expectedError: `variables[0].expression: Invalid value: "114 + '514'": compilation failed: ERROR: <input>:1:5: found no matching overload for '_+_' applied to '(int, string)`,
		},
		{
			name: "validation referred to non-existing variable",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "foo",
						Expression: "1 + 1",
					},
					{
						Name:       "bar",
						Expression: "variables.foo + 1",
					},
				},
				Validations: []Validation{
					{
						Expression: "variables.foo > 1", // correct
					},
					{
						Expression: "variables.replicas == 2", // replicas undefined
					},
				},
			},

			expectedError: `validations[1].expression: Invalid value: "variables.replicas == 2": compilation failed: ERROR: <input>:1:10: undefined field 'replicas'`,
		},
		{
			name: "variables wrong order",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "correct",
						Expression: "object",
					},
					{
						Name:       "bar", // should go below foo
						Expression: "variables.foo + 1",
					},
					{
						Name:       "foo",
						Expression: "1 + 1",
					},
				},
				Validations: []Validation{
					{
						Expression: "variables.foo > 1", // correct
					},
				},
			},
			expectedError: `variables[1].expression: Invalid value: "variables.foo + 1": compilation failed: ERROR: <input>:1:10: undefined field 'foo'`,
		},
		{
			name: "invalid ParamKind",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "correct",
						Expression: "object",
					},
				},
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "",
					Kind:       "",
				},
				Validations: []Validation{
					{
						Expression: "0 > 1",
					},
				},
			},
			expectedError: `paramKind must have both APIVersion and Kind specified`,
		},
		{
			name: "invalid ParamRef",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "correct",
						Expression: "object",
					},
				},
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ParamRef: &admissionregistration.ParamRef{
					Name:     "",
					Selector: nil,
				},
				Validations: []Validation{
					{
						Expression: "0 > 1",
					},
				},
			},
			expectedError: `paramRef must have either Name or Selector specified`,
		},
		{
			name: "ParamRef cannot have both Name and Selector",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "correct",
						Expression: "object",
					},
				},
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ParamRef: &admissionregistration.ParamRef{
					Name: "my-config",
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "my-app"},
					},
				},
				Validations: []Validation{
					{
						Expression: "0 > 1",
					},
				},
			},
			expectedError: `paramRef cannot have both Name and Selector specified`,
		},
		{
			name: "ParamRef must define a valid ParameterNotFoundAction",
			settings: Settings{
				Variables: []Variable{
					{
						Name:       "correct",
						Expression: "object",
					},
				},
				ParamKind: &admissionregistration.ParamKind{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ParamRef: &admissionregistration.ParamRef{
					Name: "my-config",
				},
				Validations: []Validation{
					{
						Expression: "0 > 1",
					},
				},
			},
			expectedError: `parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified`,
		},
		{
			name: "failurePolicy allow values",
			settings: Settings{
				FailurePolicy: "Other",
				Variables: []Variable{
					{
						Name:       "correct",
						Expression: "object",
					},
				},
				Validations: []Validation{
					{
						Expression: "0 > 1",
					},
				},
			},
			expectedError: `failurePolicy must be either 'Ignore' or 'Fail'`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings, err := json.Marshal(test.settings)
			require.NoError(t, err)

			response, err := ValidateSettings(settings)
			require.NoError(t, err)

			settingsValidationResponse := protocol.SettingsValidationResponse{}
			err = json.Unmarshal(response, &settingsValidationResponse)
			require.NoError(t, err)

			assert.False(t, settingsValidationResponse.Valid)
			assert.Contains(t, *settingsValidationResponse.Message, test.expectedError)
		})
	}
}

func TestSerialization(t *testing.T) {
	action := admissionregistration.DenyAction
	expectedsettings := Settings{
		FailurePolicy: admissionregistration.Ignore,
		Variables: []Variable{
			{
				Name:       "correct",
				Expression: "object",
			},
		},
		ParamKind: &admissionregistration.ParamKind{
			APIVersion: "v1",
			Kind:       "kind",
		},
		ParamRef: &admissionregistration.ParamRef{
			Name:      "name",
			Namespace: "namespace",
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "my-app",
				},
			},
			ParameterNotFoundAction: &action,
		},
		Validations: []Validation{
			{
				Expression:        "0 <= 2",
				MessageExpression: "Invalid value",
				Reason:            "Unauthorized",
			},
		},
	}
	_, err := json.Marshal(expectedsettings)
	require.NoError(t, err)
	//nolint:musttag // no need to validate this on tests
	_, err = yaml.Marshal(expectedsettings)
	require.NoError(t, err)

	settingsString := []byte(`
	
{
	"failurePolicy": "Ignore",
	"variables": [
	{"name": "correct", "expression": "object"}
	],
  "paramKind": {
    "APIVersion": "v1",
    "Kind": "kind"
  },
  "paramRef": {
    "Name": "name",
    "Namespace": "namespace",
  	"Selector": {"matchLabels":{"app":"my-app"}},
    "ParameterNotFoundAction": "Deny"
  },
  "validations": [
    {
      "expression": "0 <= 2",
      "messageExpression": "Invalid value",
      "reason": "Unauthorized"
    }
  ]
}
`)
	settings := Settings{}
	err = json.Unmarshal(settingsString, &settings)
	require.NoError(t, err)
	require.Equal(t, settings, expectedsettings)
}

func TestParameterNotFoundValidationAfterSerialization(t *testing.T) {
	settingsString := []byte(`
{
	"variables": [
	{"name": "correct", "expression": "object"}
	],
  "paramKind": {
    "APIVersion": "v1",
    "Kind": "kind"
  },
  "paramRef": {
    "Name": "name",
    "Namespace": "namespace",
    "ParameterNotFoundAction": "Other"
  },
  "validations": [
    {
      "expression": "0 <= 2",
      "reason": "Unauthorized"
    }
  ]
}
`)
	response, err := ValidateSettings(settingsString)
	require.NoError(t, err)
	settingsValidationResponse := protocol.SettingsValidationResponse{}
	err = json.Unmarshal(response, &settingsValidationResponse)
	require.NoError(t, err)

	require.False(t, settingsValidationResponse.Valid)
	require.NotNil(t, settingsValidationResponse.Message)
	require.Contains(t, *settingsValidationResponse.Message, "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified")
}

func TestFailurePolicySerialization(t *testing.T) {
	settingsString := []byte(`
	
{
	"variables": [
	{"name": "correct", "expression": "object"}
	],
  "validations": [
    {
      "expression": "0 <= 2",
      "messageExpression": "Invalid value",
      "reason": "Unauthorized"
    }
  ]
}
`)
	settings := Settings{}
	err := json.Unmarshal(settingsString, &settings)
	require.NoError(t, err)
	require.Equal(t, admissionregistration.Fail, settings.FailurePolicy)
}
