package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wristband-dev/go-auth/rand"
)

func TestNewConfidentialSigner(t *testing.T) {
	t.Run("with provided secret key", func(t *testing.T) {
		secretKey := []byte("test-secret-key-32-bytes-long!!")
		signer := NewConfidentialSigner(secretKey)

		if string(signer.SecretKey) != string(secretKey) {
			t.Errorf("Expected SecretKey to match provided key")
		}
	})

	t.Run("with nil secret key", func(t *testing.T) {
		signer := NewConfidentialSigner(nil)

		if len(signer.SecretKey) != 32 {
			t.Errorf("Expected SecretKey to be 32 bytes, got %d", len(signer.SecretKey))
		}
	})
}

func TestWriteCookie(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := WriteCookie(w, cookie)
		if err != nil {
			t.Fatalf("WriteCookie failed: %v", err)
		}

		result := w.Result()
		cookies := result.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("Expected 1 cookie, got %d", len(cookies))
		}

		expectedValue := base64.URLEncoding.EncodeToString([]byte("test-value"))
		if cookies[0].Value != expectedValue {
			t.Errorf("Expected cookie value '%s', got '%s'", expectedValue, cookies[0].Value)
		}
		if cookies[0].Name != "test" {
			t.Errorf("Expected cookie name 'test', got '%s'", cookies[0].Name)
		}
	})

	t.Run("value too long error", func(t *testing.T) {
		w := httptest.NewRecorder()
		longValue := strings.Repeat("a", 4000)
		cookie := http.Cookie{
			Name:  "test",
			Value: longValue,
		}

		err := WriteCookie(w, cookie)
		if !errors.Is(err, ErrValueTooLong) {
			t.Errorf("Expected ErrValueTooLong, got %v", err)
		}
	})
}

func TestReadCookie(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		value := "test-value"
		encodedValue := base64.URLEncoding.EncodeToString([]byte(value))

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: encodedValue,
		})

		result, err := ReadCookie(StandardRequest(req), "test")
		if err != nil {
			t.Fatalf("ReadCookie failed: %v", err)
		}

		if result != value {
			t.Errorf("Expected value '%s', got '%s'", value, result)
		}
	})

	t.Run("cookie not found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		_, err := ReadCookie(StandardRequest(req), "nonexistent")
		if err == nil {
			t.Error("Expected error for nonexistent cookie")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: "invalid-base64!@#",
		})

		_, err := ReadCookie(StandardRequest(req), "test")
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue, got %v", err)
		}
	})
}

func TestWriteSigned(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		w := httptest.NewRecorder()
		secretKey := []byte("test-secret-key")
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := WriteSigned(w, cookie, secretKey)
		if err != nil {
			t.Fatalf("WriteSigned failed: %v", err)
		}

		result := w.Result()
		cookies := result.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("Expected 1 cookie, got %d", len(cookies))
		}

		decodedValue, err := base64.URLEncoding.DecodeString(cookies[0].Value)
		if err != nil {
			t.Fatalf("Failed to decode cookie value: %v", err)
		}

		if len(decodedValue) < sha256.Size {
			t.Error("Cookie value should contain signature")
		}

		signature := decodedValue[:sha256.Size]
		value := string(decodedValue[sha256.Size:])

		if value != "test-value" {
			t.Errorf("Expected value 'test-value', got '%s'", value)
		}

		mac := hmac.New(sha256.New, secretKey)
		mac.Write([]byte("test"))
		mac.Write([]byte("test-value"))
		expectedSignature := mac.Sum(nil)

		if !hmac.Equal(signature, expectedSignature) {
			t.Error("Signature verification failed")
		}
	})
}

func TestReadSigned(t *testing.T) {
	secretKey := []byte("test-secret-key")

	t.Run("successful read", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := WriteSigned(w, cookie, secretKey)
		if err != nil {
			t.Fatalf("WriteSigned failed: %v", err)
		}

		result := w.Result()
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range result.Cookies() {
			req.AddCookie(c)
		}

		value, err := ReadSigned(StandardRequest(req), "test", secretKey)
		if err != nil {
			t.Fatalf("ReadSigned failed: %v", err)
		}

		if value != "test-value" {
			t.Errorf("Expected value 'test-value', got '%s'", value)
		}
	})

	t.Run("tampered value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		tamperedValue := base64.URLEncoding.EncodeToString([]byte("tampered-signature-and-valuetampered-value"))
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: tamperedValue,
		})

		_, err := ReadSigned(StandardRequest(req), "test", secretKey)
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for tampered cookie, got %v", err)
		}
	})

	t.Run("value too short", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		shortValue := base64.URLEncoding.EncodeToString([]byte("short"))
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: shortValue,
		})

		_, err := ReadSigned(StandardRequest(req), "test", secretKey)
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for short value, got %v", err)
		}
	})

	t.Run("wrong secret key", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := WriteSigned(w, cookie, secretKey)
		if err != nil {
			t.Fatalf("WriteSigned failed: %v", err)
		}

		result := w.Result()
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range result.Cookies() {
			req.AddCookie(c)
		}

		wrongKey := []byte("wrong-secret-key")
		_, err = ReadSigned(StandardRequest(req), "test", wrongKey)
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for wrong secret key, got %v", err)
		}
	})
}

func TestWriteEncrypted(t *testing.T) {
	secretKey := rand.GenerateRandomKey(32)
	signer := NewConfidentialSigner(secretKey)

	t.Run("successful write", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := signer.WriteEncrypted(w, cookie)
		if err != nil {
			t.Fatalf("WriteEncrypted failed: %v", err)
		}

		result := w.Result()
		cookies := result.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("Expected 1 cookie, got %d", len(cookies))
		}

		if cookies[0].Name != "test" {
			t.Errorf("Expected cookie name 'test', got '%s'", cookies[0].Name)
		}

		if cookies[0].Value == cookie.Value {
			t.Error("Cookie value should be encrypted")
		}
	})

	t.Run("invalid secret key", func(t *testing.T) {
		invalidSigner := NewConfidentialSigner([]byte("short"))
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := invalidSigner.WriteEncrypted(w, cookie)
		if err == nil {
			t.Error("Expected error for invalid secret key length")
		}
	})
}

func TestReadEncrypted(t *testing.T) {
	secretKey := rand.GenerateRandomKey(32)
	signer := NewConfidentialSigner(secretKey)

	t.Run("successful read", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := signer.WriteEncrypted(w, cookie)
		if err != nil {
			t.Fatalf("WriteEncrypted failed: %v", err)
		}

		result := w.Result()
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range result.Cookies() {
			req.AddCookie(c)
		}

		value, err := signer.ReadEncrypted(StandardRequest(req), "test")
		if err != nil {
			t.Fatalf("ReadEncrypted failed: %v", err)
		}

		if value != "test-value" {
			t.Errorf("Expected value 'test-value', got '%s'", value)
		}
	})

	t.Run("tampered value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		tamperedValue := base64.URLEncoding.EncodeToString([]byte("tampered-encrypted-data"))
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: tamperedValue,
		})

		_, err := signer.ReadEncrypted(StandardRequest(req), "test")
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for tampered cookie, got %v", err)
		}
	})

	t.Run("value too short", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		shortValue := base64.URLEncoding.EncodeToString([]byte("short"))
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: shortValue,
		})

		_, err := signer.ReadEncrypted(StandardRequest(req), "test")
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for short value, got %v", err)
		}
	})

	t.Run("wrong secret key", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := signer.WriteEncrypted(w, cookie)
		if err != nil {
			t.Fatalf("WriteEncrypted failed: %v", err)
		}

		result := w.Result()
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range result.Cookies() {
			req.AddCookie(c)
		}

		wrongSigner := NewConfidentialSigner(rand.GenerateRandomKey(32))
		_, err = wrongSigner.ReadEncrypted(StandardRequest(req), "test")
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for wrong secret key, got %v", err)
		}
	})

	t.Run("wrong cookie name", func(t *testing.T) {
		w := httptest.NewRecorder()
		cookie := http.Cookie{
			Name:  "test",
			Value: "test-value",
		}

		err := signer.WriteEncrypted(w, cookie)
		if err != nil {
			t.Fatalf("WriteEncrypted failed: %v", err)
		}

		result := w.Result()
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range result.Cookies() {
			req.AddCookie(&http.Cookie{
				Name:  "different-name",
				Value: c.Value,
			})
		}

		_, err = signer.ReadEncrypted(StandardRequest(req), "different-name")
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for wrong cookie name, got %v", err)
		}
	})

	t.Run("invalid plaintext format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		invalidPlaintext := []byte("invalid-format-without-colon")
		fakeEncrypted := base64.URLEncoding.EncodeToString(invalidPlaintext)
		req.AddCookie(&http.Cookie{
			Name:  "test",
			Value: fakeEncrypted,
		})

		_, err := signer.ReadEncrypted(StandardRequest(req), "test")
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Expected ErrInvalidValue for invalid plaintext format, got %v", err)
		}
	})
}

func TestCookieRoundTrip(t *testing.T) {
	secretKey := rand.GenerateRandomKey(32)
	signer := NewConfidentialSigner(secretKey)

	testCases := []struct {
		name        string
		cookieName  string
		cookieValue string
		writeFunc   func(http.ResponseWriter, http.Cookie) error
		readFunc    func(CookieRequest, string) (string, error)
	}{
		{
			name:        "basic cookie",
			cookieName:  "basic",
			cookieValue: "basic-value",
			writeFunc:   WriteCookie,
			readFunc:    ReadCookie,
		},
		{
			name:        "signed cookie",
			cookieName:  "signed",
			cookieValue: "signed-value",
			writeFunc: func(w http.ResponseWriter, c http.Cookie) error {
				return WriteSigned(w, c, secretKey)
			},
			readFunc: func(r CookieRequest, name string) (string, error) {
				return ReadSigned(r, name, secretKey)
			},
		},
		{
			name:        "encrypted cookie",
			cookieName:  "encrypted",
			cookieValue: "encrypted-value",
			writeFunc:   signer.WriteEncrypted,
			readFunc:    signer.ReadEncrypted,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			cookie := http.Cookie{
				Name:  tc.cookieName,
				Value: tc.cookieValue,
			}

			err := tc.writeFunc(w, cookie)
			if err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			result := w.Result()
			req := httptest.NewRequest("GET", "/", nil)
			for _, c := range result.Cookies() {
				req.AddCookie(c)
			}

			value, err := tc.readFunc(StandardRequest(req), tc.cookieName)
			if err != nil {
				t.Fatalf("Read failed: %v", err)
			}

			if value != tc.cookieValue {
				t.Errorf("Expected value '%s', got '%s'", tc.cookieValue, value)
			}
		})
	}
}

func TestErrorVariables(t *testing.T) {
	if ErrValueTooLong == nil {
		t.Error("ErrValueTooLong should be defined")
	}
	if ErrInvalidValue == nil {
		t.Error("ErrInvalidValue should be defined")
	}
	if ErrValueTooLong.Error() == "" {
		t.Error("ErrValueTooLong should have an error message")
	}
	if ErrInvalidValue.Error() == "" {
		t.Error("ErrInvalidValue should have an error message")
	}
}
