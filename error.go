package goauth

import (
	"fmt"
)

type InvalidParameter string

func (e InvalidParameter) Error() string {
	return "query parameter " + string(e) + " is invalid"
}

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
