package goauth

import (
	"errors"
	"fmt"
)

// InvalidParameterError represents an error for an invalid query parameter.
type InvalidParameterError string

func (e InvalidParameterError) Error() string {
	return "query parameter " + string(e) + " is invalid"
}

// WristbandError represents an error returned by the Wristband API.
type WristbandError struct {
	Message string
	Code    string
}

// Error implements the error interface.
func (e WristbandError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewWristbandError creates a new WristbandError.
func NewWristbandError(err, description string) error {
	return WristbandError{
		Message: description,
		Code:    err,
	}
}

// InvalidCallbackQueryParameterError creates an InvalidCallbackError for an invalid query parameter.
func InvalidCallbackQueryParameterError(parameter string) *InvalidCallbackError {
	return &InvalidCallbackError{
		Message: "query parameter " + parameter + " is invalid",
	}
}

// InvalidCallbackError represents an error for an invalid callback request from Wristband.
type InvalidCallbackError struct {
	Message string
}

func (e InvalidCallbackError) Error() string {
	return fmt.Sprintf("invalid request received from Wristband during callback: %s", e.Message)
}

// RequestError checks if the query values contain an error and returns a WristbandError if so.
func RequestError(queryValues QueryValueResolver) error {
	if queryValues == nil {
		return nil
	}
	if !queryValues.Has("error") && !queryValues.Has("error_description") {
		return nil
	}

	return &WristbandError{
		Message: queryValues.Get("error_description"),
		Code:    queryValues.Get("error"),
	}
}

// RedirectError represents an error that requires a redirect.
type RedirectError struct {
	Message string
	URL     string
}

func (e RedirectError) Error() string {
	return e.Message
}

// NewRedirectError creates a new RedirectError.
func NewRedirectError(err, url string) error {
	return RedirectError{
		Message: err,
		URL:     url,
	}
}

// IsRedirectError checks if the error is a RedirectError.
func IsRedirectError(err error) (*RedirectError, bool) {
	var redirectError *RedirectError
	if errors.As(err, &redirectError) {
		return redirectError, true
	}
	return nil, false
}
