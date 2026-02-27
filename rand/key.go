// Package rand provides functions to generate random strings and keys.
package rand

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// GenerateRandomString creates a random string of specified length
func GenerateRandomString(length int) string {
	return base64.RawURLEncoding.EncodeToString(GenerateRandomKey(length))
}

// GenerateRandomCookieName creates a random string of specified length
func GenerateRandomCookieName(length int) string {
	return base64.RawURLEncoding.EncodeToString(GenerateRandomKey(length))
}

// GenerateCodeChallenge generates a code challenge from a code verifier for PKCE
func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, codeVerifier)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// GenerateRandomKey creates a random key of specified length
func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	if _, err := rand.Read(k); err != nil {
		return nil
	}
	return k
}
