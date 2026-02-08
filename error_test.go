package goauth

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
)

func TestInvalidParameterError(t *testing.T) {
	err := InvalidParameterError("code")
	expected := "query parameter code is invalid"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

func TestWristbandError(t *testing.T) {
	err := WristbandError{Message: "something broke", Code: "server_error"}
	expected := "server_error: something broke"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

func TestNewWristbandError(t *testing.T) {
	err := NewWristbandError("invalid_grant", "the grant is expired")
	var wErr WristbandError
	if !errors.As(err, &wErr) {
		t.Fatal("Expected WristbandError type")
	}
	if wErr.Code != "invalid_grant" {
		t.Errorf("Expected code %q, got %q", "invalid_grant", wErr.Code)
	}
	if wErr.Message != "the grant is expired" {
		t.Errorf("Expected message %q, got %q", "the grant is expired", wErr.Message)
	}
}

func TestInvalidCallbackQueryParameterError(t *testing.T) {
	err := InvalidCallbackQueryParameterError("state")
	if err == nil {
		t.Fatal("Expected non-nil error")
	}
	if err.Message != "query parameter state is invalid" {
		t.Errorf("Expected message containing 'state', got %q", err.Message)
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("Error string should not be empty")
	}
}

func TestInvalidCallbackError_Error(t *testing.T) {
	err := InvalidCallbackError{Message: "missing code"}
	expected := "invalid request received from Wristband during callback: missing code"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

func TestRequestError(t *testing.T) {
	t.Run("nil query values", func(t *testing.T) {
		err := RequestError(nil)
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
	})

	t.Run("no error params", func(t *testing.T) {
		q := url.Values{}
		q.Set("code", "abc")
		err := RequestError(q)
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
	})

	t.Run("with error param", func(t *testing.T) {
		q := url.Values{}
		q.Set("error", "access_denied")
		q.Set("error_description", "user denied access")
		err := RequestError(q)
		if err == nil {
			t.Fatal("Expected non-nil error")
		}
		var wErr *WristbandError
		if !errors.As(err, &wErr) {
			t.Fatal("Expected *WristbandError type")
		}
		if wErr.Code != "access_denied" {
			t.Errorf("Expected code %q, got %q", "access_denied", wErr.Code)
		}
		if wErr.Message != "user denied access" {
			t.Errorf("Expected message %q, got %q", "user denied access", wErr.Message)
		}
	})

	t.Run("with error_description only", func(t *testing.T) {
		q := url.Values{}
		q.Set("error_description", "something went wrong")
		err := RequestError(q)
		if err == nil {
			t.Fatal("Expected non-nil error")
		}
	})
}

func TestRedirectError(t *testing.T) {
	err := RedirectError{Message: "redirect needed", URL: "https://example.com/login", Reason: "no session"}
	if err.Error() != "redirect needed" {
		t.Errorf("Expected %q, got %q", "redirect needed", err.Error())
	}
}

func TestNewRedirectError(t *testing.T) {
	err := NewRedirectError("login required", "https://example.com/login")
	var rErr *RedirectError
	if !errors.As(err, &rErr) {
		t.Fatal("Expected RedirectError type")
	}
	if rErr.Message != "login required" {
		t.Errorf("Expected message %q, got %q", "login required", rErr.Message)
	}
	if rErr.URL != "https://example.com/login" {
		t.Errorf("Expected URL %q, got %q", "https://example.com/login", rErr.URL)
	}
}

func TestIsRedirectError(t *testing.T) {
	t.Run("from NewRedirectError", func(t *testing.T) {
		err := NewRedirectError("redirect", "https://example.com")
		rErr, ok := IsRedirectError(err)
		if !ok {
			t.Fatal("Expected IsRedirectError to return true")
		}
		if rErr.URL != "https://example.com" {
			t.Errorf("Expected URL %q, got %q", "https://example.com", rErr.URL)
		}
	})

	t.Run("is not redirect error", func(t *testing.T) {
		err := fmt.Errorf("some other error")
		rErr, ok := IsRedirectError(err)
		if ok {
			t.Fatal("Expected IsRedirectError to return false")
		}
		if rErr != nil {
			t.Error("Expected nil RedirectError")
		}
	})

	t.Run("wrapped redirect error", func(t *testing.T) {
		inner := NewRedirectError("inner", "https://example.com/inner")
		wrapped := fmt.Errorf("outer: %w", inner)
		rErr, ok := IsRedirectError(wrapped)
		if !ok {
			t.Fatal("Expected IsRedirectError to find wrapped RedirectError")
		}
		if rErr.URL != "https://example.com/inner" {
			t.Errorf("Expected URL %q, got %q", "https://example.com/inner", rErr.URL)
		}
	})
}
