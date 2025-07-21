package errors

import (
	"errors"
	"fmt"
)

type ErrorType string

const (
	ErrorTypeValidation ErrorType = "validation_error"
	ErrorTypeAuth       ErrorType = "authentication_error"
	ErrorTypeNotFound   ErrorType = "not_found"
	ErrorTypeInternal   ErrorType = "internal_error"
	ErrorTypeDatabase   ErrorType = "database_error"
	ErrorTypeRedis      ErrorType = "redis_error"
)

type AppError struct {
	Type    ErrorType `json:"type"`
	Message string    `json:"message"`
	Code    string    `json:"code,omitempty"`
	Err     error     `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func NewError(errorType ErrorType, message string, err error) *AppError {
	return &AppError{
		Type:    errorType,
		Message: message,
		Err:     err,
	}
}

func IsAppError(err error) (*AppError, bool) {

	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}

	return nil, false
}

func (e *AppError) GetHTTPStatus() int {
	switch e.Type {
	case ErrorTypeValidation:
		return 400
	case ErrorTypeAuth:
		return 401
	case ErrorTypeNotFound:
		return 404
	case ErrorTypeDatabase, ErrorTypeRedis, ErrorTypeInternal:
		return 500
	default:
		return 500
	}
}
