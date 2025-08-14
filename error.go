package goauth

import (
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

func (e WristbandError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

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

func RequestError(queryValues QueryValueResolver) error {
	if queryValues == nil {
		return nil
	}
	if !(queryValues.Has("error") && queryValues.Has("error_description")) {
		return nil
	}

	return &WristbandError{
		Message: queryValues.Get("error_description"),
		Code:    queryValues.Get("error"),
	}
}
