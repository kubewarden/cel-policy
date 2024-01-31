package main

import (
	"io"
	"log"
	"os"

	"github.com/kubewarden/cel-policy/internal/settings"
	"github.com/kubewarden/cel-policy/internal/validate"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Wrong usage, expected either 'validate' or 'validate-settings'")
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Panicf("Cannot read input: %v", err)
	}

	var response []byte

	switch os.Args[1] {
	case "validate":
		response, err = validate.Validate(input)
	case "validate-settings":
		response, err = settings.ValidateSettings(input)
	default:
		log.Fatalf("wrong subcommand: '%s' - use either 'validate' or 'validate-settings'", os.Args[1])
	}

	if err != nil {
		log.Fatal(err)
	}

	_, err = os.Stdout.Write(response)
	if err != nil {
		log.Fatalf("Cannot write response: %v", err)
	}
}
