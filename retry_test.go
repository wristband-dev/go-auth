package goauth

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubResponse describes a canned HTTP response returned by a stubbed transport.
type stubResponse struct {
	statusCode int
	body       string
	err        error
}

// stubHTTPClient returns an *http.Client whose transport replays the given responses in
// order, repeating the final response once they are exhausted. The returned counter
// reports how many requests were made.
func stubHTTPClient(responses ...stubResponse) (*http.Client, *atomic.Int64) {
	var calls atomic.Int64

	client := &http.Client{
		Transport: RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			idx := int(calls.Add(1)) - 1
			if idx >= len(responses) {
				idx = len(responses) - 1
			}
			stub := responses[idx]

			if stub.err != nil {
				return nil, stub.err
			}

			return &http.Response{
				StatusCode: stub.statusCode,
				Body:       io.NopCloser(strings.NewReader(stub.body)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	return client, &calls
}

func TestWithRetry_SucceedsOnFirstAttemptWithoutRetrying(t *testing.T) {
	calls := 0

	result, err := withRetry(func() (string, error) {
		calls++
		return "result", nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("Expected %q, got %q", "result", result)
	}
	if calls != 1 {
		t.Errorf("Expected 1 attempt, got %d", calls)
	}
}

func TestWithRetry_RetriesOn5xxAndEventuallySucceeds(t *testing.T) {
	calls := 0

	result, err := withRetry(func() (string, error) {
		calls++
		if calls < 3 {
			return "", &APIError{Operation: "test", StatusCode: 500, Body: "boom"}
		}
		return "result", nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("Expected %q, got %q", "result", result)
	}
	if calls != 3 {
		t.Errorf("Expected 3 attempts, got %d", calls)
	}
}

func TestWithRetry_RetriesOnNetworkErrorAndEventuallySucceeds(t *testing.T) {
	calls := 0

	result, err := withRetry(func() (string, error) {
		calls++
		if calls < 2 {
			return "", fmt.Errorf("connection refused")
		}
		return "result", nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("Expected %q, got %q", "result", result)
	}
	if calls != 2 {
		t.Errorf("Expected 2 attempts, got %d", calls)
	}
}

func TestWithRetry_DoesNotRetryOn4xx(t *testing.T) {
	calls := 0

	_, err := withRetry(func() (string, error) {
		calls++
		return "", &APIError{Operation: "test", StatusCode: 400, Body: "bad request"}
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("Expected 1 attempt for a 4xx, got %d", calls)
	}
}

func TestWithRetry_DoesNotRetryOn404(t *testing.T) {
	calls := 0

	_, err := withRetry(func() (string, error) {
		calls++
		return "", &APIError{Operation: "test", StatusCode: 404, Body: "not found"}
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("Expected 1 attempt for a 404, got %d", calls)
	}
}

func TestWithRetry_ExhaustsRetriesOnPersistent5xx(t *testing.T) {
	calls := 0

	_, err := withRetry(func() (string, error) {
		calls++
		return "", &APIError{Operation: "test", StatusCode: 503, Body: "unavailable"}
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if calls != MaxAPIRetryAttempts {
		t.Errorf("Expected %d attempts, got %d", MaxAPIRetryAttempts, calls)
	}

	apiErr, ok := IsAPIError(err)
	if !ok {
		t.Fatalf("Expected an APIError, got %T", err)
	}
	if apiErr.StatusCode != 503 {
		t.Errorf("Expected status 503, got %d", apiErr.StatusCode)
	}
}

func TestWithRetry_ExhaustsRetriesOnPersistentNetworkError(t *testing.T) {
	calls := 0

	_, err := withRetry(func() (string, error) {
		calls++
		return "", fmt.Errorf("connection refused")
	})
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if calls != MaxAPIRetryAttempts {
		t.Errorf("Expected %d attempts, got %d", MaxAPIRetryAttempts, calls)
	}
}

func TestWithRetry_AppliesExponentialBackoff(t *testing.T) {
	calls := 0

	start := time.Now()
	_, err := withRetry(func() (string, error) {
		calls++
		if calls < 3 {
			return "", &APIError{Operation: "test", StatusCode: 500, Body: "boom"}
		}
		return "result", nil
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// First retry waits APIRetryDelayMs, second waits APIRetryDelayMs*APIRetryDelayMultiplier.
	expected := time.Duration(APIRetryDelayMs)*time.Millisecond +
		time.Duration(APIRetryDelayMs*APIRetryDelayMultiplier)*time.Millisecond
	if elapsed < expected {
		t.Errorf("Expected at least %v of backoff, got %v", expected, elapsed)
	}
}

func TestWithRetry_DoesNotWaitAfterNonRetryableError(t *testing.T) {
	start := time.Now()
	_, err := withRetry(func() (string, error) {
		return "", &APIError{Operation: "test", StatusCode: 400, Body: "bad request"}
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if elapsed >= time.Duration(APIRetryDelayMs)*time.Millisecond {
		t.Errorf("Expected no backoff for a non-retryable error, waited %v", elapsed)
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"500 is retryable", &APIError{StatusCode: 500}, true},
		{"503 is retryable", &APIError{StatusCode: 503}, true},
		{"400 is not retryable", &APIError{StatusCode: 400}, false},
		{"401 is not retryable", &APIError{StatusCode: 401}, false},
		{"404 is not retryable", &APIError{StatusCode: 404}, false},
		{"network error is retryable", fmt.Errorf("connection refused"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableError(tt.err); got != tt.want {
				t.Errorf("isRetryableError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestAPIError_ErrorMessage(t *testing.T) {
	err := &APIError{Operation: "userinfo request", StatusCode: 401, Body: "Unauthorized"}

	want := "userinfo request failed with status 401: Unauthorized"
	if err.Error() != want {
		t.Errorf("Expected %q, got %q", want, err.Error())
	}
}
