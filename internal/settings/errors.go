package settings

import "fmt"

type requiredValueError struct {
	path    string
	message string
}

func newRequiredValueError(path, message string) error {
	return &requiredValueError{
		path:    path,
		message: message,
	}
}

func (e *requiredValueError) Error() string {
	return fmt.Sprintf("%s: Required value: %s", e.path, e.message)
}

type invalidValueError struct {
	path    string
	value   string
	message string
}

func newInvalidValueError(path, value, message string) error {
	return &invalidValueError{
		path:    path,
		value:   value,
		message: message,
	}
}

func (e *invalidValueError) Error() string {
	return fmt.Sprintf(`%s: Invalid value: "%s": %s:`, e.path, e.value, e.message)
}

type notSupportedValueError struct {
	path  string
	value string
}

func newNotSupportedValueError(path, value string) error {
	return &notSupportedValueError{
		path:  path,
		value: value,
	}
}

func (e *notSupportedValueError) Error() string {
	return fmt.Sprintf(`%s: Unsupported value: "%s"`, e.path, e.value)
}
