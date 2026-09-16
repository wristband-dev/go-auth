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

// APIError represents a non-2xx response received from a Wristband API call.
//
// The raw response body is preserved as an unparsed string so that a non-JSON error body
// (for example a plain-text or HTML error page served by a proxy or CDN) never causes a
// decoding failure of its own. Retry classification relies on StatusCode, so a 4xx carrying
// a non-JSON body is still correctly treated as non-retryable.
type APIError struct {
	// Operation describes the API call that failed, used to prefix the error message.
	Operation string
	// Body is the raw, unparsed response body.
	Body string
	// StatusCode is the HTTP status code returned by the Wristband API.
	StatusCode int
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("%s failed with status %d: %s", e.Operation, e.StatusCode, e.Body)
}

// IsAPIError checks if the error is an APIError.
func IsAPIError(err error) (*APIError, bool) {
	var apiError *APIError
	if errors.As(err, &apiError) {
		return apiError, true
	}
	return nil, false
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
	Reason  string
}

func (e RedirectError) Error() string {
	return e.Message
}

// NewRedirectError creates a new RedirectError.
func NewRedirectError(err, url string) error {
	return &RedirectError{
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
