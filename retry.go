package goauth

import (
	"time"
)

const (
	// MaxAPIRetryAttempts is the maximum number of attempts made for a single Wristband API call,
	// including the initial attempt.
	MaxAPIRetryAttempts = 3

	// APIRetryDelayMs is the delay before the first retry, in milliseconds.
	APIRetryDelayMs = 100

	// APIRetryDelayMultiplier is the factor the retry delay is multiplied by after each attempt,
	// producing exponential backoff.
	APIRetryDelayMultiplier = 2
)

// isRetryableError reports whether a failed Wristband API call should be retried.
//
// Only transient failures are retried: 5xx responses and network-level errors such as
// connection failures and timeouts. A 4xx response indicates a client-side problem that a
// retry cannot fix, so it is never retried.
func isRetryableError(err error) bool {
	if apiErr, ok := IsAPIError(err); ok {
		return apiErr.StatusCode >= 500
	}
	return true
}

// withRetry invokes fn, retrying transient failures with exponential backoff.
//
// It makes up to MaxAPIRetryAttempts attempts, waiting APIRetryDelayMs before the first retry
// and multiplying the delay by APIRetryDelayMultiplier after each subsequent failure. Errors
// that isRetryableError classifies as non-transient are returned immediately.
func withRetry[T any](fn func() (T, error)) (T, error) {
	var result T
	var err error

	delay := time.Duration(APIRetryDelayMs) * time.Millisecond

	for attempt := 1; attempt <= MaxAPIRetryAttempts; attempt++ {
		result, err = fn()
		if err == nil {
			return result, nil
		}

		if attempt == MaxAPIRetryAttempts || !isRetryableError(err) {
			return result, err
		}

		time.Sleep(delay)
		delay *= APIRetryDelayMultiplier
	}

	return result, err
}
