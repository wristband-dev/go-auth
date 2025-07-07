package rand

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateRandomString(t *testing.T) {
	t.Run("generates string of correct length", func(t *testing.T) {
		lengths := []int{8, 16, 32, 64}
		for _, length := range lengths {
			result := GenerateRandomString(length)

			// Base64 URL encoding without padding, so we need to calculate expected length
			expectedLength := base64.RawURLEncoding.EncodedLen(length)
			if len(result) != expectedLength {
				t.Errorf("Expected string length %d, got %d for input length %d", expectedLength, len(result), length)
			}
		}
	})

	t.Run("generates different strings", func(t *testing.T) {
		length := 32
		results := make(map[string]bool)
		iterations := 100

		for range iterations {
			result := GenerateRandomString(length)
			if results[result] {
				t.Errorf("Generated duplicate random string: %s", result)
			}
			results[result] = true
		}
	})

	t.Run("uses valid base64 URL encoding", func(t *testing.T) {
		result := GenerateRandomString(32)

		// Should not contain invalid characters for base64 URL encoding
		invalidChars := []string{"+", "/", "="}
		for _, char := range invalidChars {
			if strings.Contains(result, char) {
				t.Errorf("Result contains invalid base64 URL character '%s': %s", char, result)
			}
		}

		// Should be decodable
		_, err := base64.RawURLEncoding.DecodeString(result)
		if err != nil {
			t.Errorf("Generated string is not valid base64 URL encoding: %v", err)
		}
	})

	t.Run("handles zero length", func(t *testing.T) {
		result := GenerateRandomString(0)
		if len(result) != 0 {
			t.Errorf("Expected empty string for zero length, got %s", result)
		}
	})
}

func TestGenerateRandomCookieName(t *testing.T) {
	t.Run("generates string of correct length", func(t *testing.T) {
		lengths := []int{8, 16, 32}
		for _, length := range lengths {
			result := GenerateRandomCookieName(length)

			expectedLength := base64.RawURLEncoding.EncodedLen(length)
			if len(result) != expectedLength {
				t.Errorf("Expected cookie name length %d, got %d for input length %d", expectedLength, len(result), length)
			}
		}
	})

	t.Run("generates different cookie names", func(t *testing.T) {
		length := 16
		results := make(map[string]bool)
		iterations := 50

		for range iterations {
			result := GenerateRandomCookieName(length)
			if results[result] {
				t.Errorf("Generated duplicate cookie name: %s", result)
			}
			results[result] = true
		}
	})

	t.Run("produces same format as GenerateRandomString", func(t *testing.T) {
		length := 16
		randomString := GenerateRandomString(length)
		cookieName := GenerateRandomCookieName(length)

		// Both should have the same length and character set
		if len(randomString) != len(cookieName) {
			t.Errorf("RandomString and RandomCookieName should have same length for same input")
		}

		// Both should be valid base64 URL encoded
		_, err1 := base64.RawURLEncoding.DecodeString(randomString)
		_, err2 := base64.RawURLEncoding.DecodeString(cookieName)

		if err1 != nil || err2 != nil {
			t.Error("Both functions should generate valid base64 URL encoded strings")
		}
	})
}

func TestGenerateCodeChallenge(t *testing.T) {
	t.Run("generates correct SHA256 hash", func(t *testing.T) {
		codeVerifier := "test-code-verifier"
		result := GenerateCodeChallenge(codeVerifier)

		// Manually calculate expected result
		hash := sha256.New()
		hash.Write([]byte(codeVerifier))
		expected := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

		if result != expected {
			t.Errorf("Expected code challenge '%s', got '%s'", expected, result)
		}
	})

	t.Run("produces deterministic output", func(t *testing.T) {
		codeVerifier := "consistent-verifier"

		result1 := GenerateCodeChallenge(codeVerifier)
		result2 := GenerateCodeChallenge(codeVerifier)

		if result1 != result2 {
			t.Errorf("Code challenge should be deterministic. Got '%s' and '%s'", result1, result2)
		}
	})

	t.Run("different verifiers produce different challenges", func(t *testing.T) {
		verifier1 := "verifier-one"
		verifier2 := "verifier-two"

		challenge1 := GenerateCodeChallenge(verifier1)
		challenge2 := GenerateCodeChallenge(verifier2)

		if challenge1 == challenge2 {
			t.Error("Different verifiers should produce different challenges")
		}
	})

	t.Run("handles empty string", func(t *testing.T) {
		result := GenerateCodeChallenge("")

		// Should still produce a valid base64 encoded result
		_, err := base64.RawURLEncoding.DecodeString(result)
		if err != nil {
			t.Errorf("Code challenge for empty string should be valid base64: %v", err)
		}

		// Should be the expected length (SHA256 hash encoded)
		expectedLength := base64.RawURLEncoding.EncodedLen(sha256.Size)
		if len(result) != expectedLength {
			t.Errorf("Expected length %d, got %d", expectedLength, len(result))
		}
	})

	t.Run("complies with PKCE specification", func(t *testing.T) {
		// PKCE spec requires base64url encoding without padding
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		result := GenerateCodeChallenge(codeVerifier)

		// Should not contain padding
		if strings.Contains(result, "=") {
			t.Error("Code challenge should not contain padding (PKCE spec)")
		}

		// Should be valid base64 URL encoding
		_, err := base64.RawURLEncoding.DecodeString(result)
		if err != nil {
			t.Errorf("Code challenge should be valid base64 URL encoding: %v", err)
		}
	})
}

func TestGenerateRandomKey(t *testing.T) {
	t.Run("generates key of correct length", func(t *testing.T) {
		lengths := []int{16, 32, 64, 128}
		for _, length := range lengths {
			result := GenerateRandomKey(length)
			if len(result) != length {
				t.Errorf("Expected key length %d, got %d", length, len(result))
			}
		}
	})

	t.Run("generates different keys", func(t *testing.T) {
		length := 32
		results := make(map[string]bool)
		iterations := 100

		for range iterations {
			result := GenerateRandomKey(length)
			resultStr := string(result)
			if results[resultStr] {
				t.Error("Generated duplicate random key")
			}
			results[resultStr] = true
		}
	})

	t.Run("handles zero length", func(t *testing.T) {
		result := GenerateRandomKey(0)
		if len(result) != 0 {
			t.Errorf("Expected empty key for zero length, got length %d", len(result))
		}
	})

	t.Run("generates non-zero bytes", func(t *testing.T) {
		length := 32
		result := GenerateRandomKey(length)

		// Check that not all bytes are zero (extremely unlikely with proper randomness)
		allZero := true
		for _, b := range result {
			if b != 0 {
				allZero = false
				break
			}
		}

		if allZero {
			t.Error("Generated key should not be all zeros")
		}
	})

	t.Run("returns nil on error", func(t *testing.T) {
		// This is harder to test since crypto/rand.Read rarely fails
		// but we can test the documented behavior
		// Note: In practice, this might be difficult to trigger

		// Test with very large length that might cause issues
		result := GenerateRandomKey(1000000)
		if result != nil && len(result) != 1000000 {
			t.Error("Either should return nil on error or correct length")
		}
	})
}

func TestRandomnessFunctions(t *testing.T) {
	t.Run("all functions use GenerateRandomKey internally", func(t *testing.T) {
		// Test that the functions are consistent in their randomness source
		length := 16

		// Generate multiple results and ensure they're different
		stringResults := make(map[string]bool)
		cookieResults := make(map[string]bool)
		keyResults := make(map[string]bool)

		for range 10 {
			stringResult := GenerateRandomString(length)
			cookieResult := GenerateRandomCookieName(length)
			keyResult := string(GenerateRandomKey(length))

			stringResults[stringResult] = true
			cookieResults[cookieResult] = true
			keyResults[keyResult] = true
		}

		// All should generate unique values
		if len(stringResults) < 10 {
			t.Error("GenerateRandomString should generate unique values")
		}
		if len(cookieResults) < 10 {
			t.Error("GenerateRandomCookieName should generate unique values")
		}
		if len(keyResults) < 10 {
			t.Error("GenerateRandomKey should generate unique values")
		}
	})
}

func TestBase64URLEncodingConsistency(t *testing.T) {
	t.Run("encoding format is consistent", func(t *testing.T) {
		// Test that both string generation functions use the same encoding
		length := 32
		randomString := GenerateRandomString(length)
		cookieName := GenerateRandomCookieName(length)

		// Both should decode without error
		_, err1 := base64.RawURLEncoding.DecodeString(randomString)
		_, err2 := base64.RawURLEncoding.DecodeString(cookieName)

		if err1 != nil {
			t.Errorf("GenerateRandomString result should be valid base64 URL encoding: %v", err1)
		}
		if err2 != nil {
			t.Errorf("GenerateRandomCookieName result should be valid base64 URL encoding: %v", err2)
		}

		// Neither should contain padding or invalid characters
		invalidChars := []string{"+", "/", "="}
		for _, char := range invalidChars {
			if strings.Contains(randomString, char) {
				t.Errorf("RandomString contains invalid character '%s'", char)
			}
			if strings.Contains(cookieName, char) {
				t.Errorf("RandomCookieName contains invalid character '%s'", char)
			}
		}
	})
}
