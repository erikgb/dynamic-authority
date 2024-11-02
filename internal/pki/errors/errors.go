package errors

import "fmt"

type invalidDataError struct{ error }

func NewInvalidData(str string, obj ...interface{}) error {
	return &invalidDataError{error: fmt.Errorf(str, obj...)}
}
