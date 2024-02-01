package cel

import (
	"regexp"
	"slices"
)

var (
	celIdentRegex = regexp.MustCompile("^[_a-zA-Z][_a-zA-Z0-9]*$")
	celReserved   = []string{
		"true", "false", "null", "in",
		"as", "break", "const", "continue", "else",
		"for", "function", "if", "import", "let",
		"loop", "package", "namespace", "return",
		"var", "void", "while",
	}
)

func IsCELIdentifier(name string) bool {
	// IDENT          ::= [_a-zA-Z][_a-zA-Z0-9]* - RESERVED
	// BOOL_LIT       ::= "true" | "false"
	// NULL_LIT       ::= "null"
	// RESERVED       ::= BOOL_LIT | NULL_LIT | "in"
	// 	 | "as" | "break" | "const" | "continue" | "else"
	// 	 | "for" | "function" | "if" | "import" | "let"
	// 	 | "loop" | "package" | "namespace" | "return"
	// 	 | "var" | "void" | "while"
	return celIdentRegex.MatchString(name) && !slices.Contains(celReserved, name)
}
