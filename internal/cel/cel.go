package cel

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/kubewarden/cel-policy/internal/cel/library"
	k8sLibrary "k8s.io/apiserver/pkg/cel/library"
)

type Compiler struct {
	env *cel.Env
}

// variables is a placeholder type for the variables object.
// This is needed in the parse/check phase, where the variables
// are added sequentially to the CEL environment.
// It's not possible to use a cel.DynType, because the compiler
// will not complain about undeclared variables.
type variables struct{}

func NewCompiler() (*Compiler, error) {
	env, err := cel.NewEnv(
		// Kubernetes 1.29 options
		cel.HomogeneousAggregateLiterals(),
		cel.EagerlyValidateDeclarations(true),
		cel.DefaultUTCTimeZone(true),
		cel.CrossTypeNumericComparisons(true),
		cel.OptionalTypes(),
		cel.ASTValidators(
			cel.ValidateDurationLiterals(),
			cel.ValidateTimestampLiterals(),
			cel.ValidateRegexLiterals(),
			cel.ValidateHomogeneousAggregateLiterals(),
		),

		// Kubernetes 1.29 libraries and extensions
		ext.Sets(),
		//nolint:mnd // extract the number 2 to a constant will not make the code more readable
		ext.Strings(ext.StringsVersion(2)),
		// allow base64 encoding/decoding
		ext.Encoders(),
		k8sLibrary.URLs(),
		k8sLibrary.Regex(),
		k8sLibrary.Lists(),
		k8sLibrary.Quantity(),
		// TODO: introduce the Authz kubernetes extension
		// library.Authz(),

		// Variables
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		ext.NativeTypes(reflect.TypeOf(&variables{})),
		cel.Variable("variables", cel.ObjectType("cel.variables")),
		// TODO: change this to cel.NativeType by using kw generated k8s objects
		// once the CEL library supports binding nested objects.
		/// See: https://github.com/google/cel-go/issues/885
		cel.Variable("request", cel.DynType),
		cel.Variable("namespaceObject", cel.DynType),

		// Kubewarden host capabilities libraries
		library.Kubernetes(),
		library.OCI(),
		library.Sigstore(),
		library.Crypto(),
		library.Net(),
	)
	if err != nil {
		return nil, err
	}

	return &Compiler{env: env}, nil
}

func (c *Compiler) CompileCELExpression(expression string) (*cel.Ast, error) {
	ast, issues := c.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compilation failed: %w", issues.Err())
	}

	return ast, nil
}

func (c *Compiler) EvalCELExpression(
	vars map[string]interface{}, ast *cel.Ast,
) (ref.Val, error) {
	prog, err := c.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, err
	}

	val, _, err := prog.Eval(vars)
	if err != nil {
		return nil, err
	}

	return val, nil
}

func (c *Compiler) ValidateBoolExpression(expression string) error {
	ast, err := c.CompileCELExpression(expression)
	if err != nil {
		return err
	}

	if ast.OutputType() != types.BoolType {
		return errors.New("must evaluate to bool")
	}

	return nil
}

func (c *Compiler) ValidateStringExpression(expression string) error {
	ast, err := c.CompileCELExpression(expression)
	if err != nil {
		return err
	}

	if ast.OutputType() != types.StringType {
		return errors.New("must evaluate to string")
	}

	return nil
}

func (c *Compiler) AddVariable(name string, t *cel.Type) error {
	env, err := c.env.Extend(cel.Variable(fmt.Sprintf("variables.%s", name), t))
	if err != nil {
		return err
	}

	c.env = env

	return nil
}
