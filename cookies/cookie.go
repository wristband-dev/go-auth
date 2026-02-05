// Package cookies provides functionality for reading and writing secure cookies.
package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/wristband-dev/go-auth/rand"
)

var (
	// ErrValueTooLong is returned when a cookie value exceeds the maximum allowed length.
	ErrValueTooLong = errors.New("cookie value too long")
	// ErrInvalidValue is returned when a cookie value is not valid.
	ErrInvalidValue = errors.New("invalid cookie value")
)

// RequestContext is an interface that provides methods for reading and writing cookies in a request.
type RequestContext interface {
	ReadCookie(name string) (string, error)
	WriteCookie(key, value string)
}

// NewCookieEncryptor creates a new CookieEncryptor with the provided secret key.
func NewCookieEncryptor(secretKey []byte) (CookieEncryptor, error) {
	if secretKey == nil {
		secretKey = rand.GenerateRandomKey(32)
	}
	encryptor := CookieEncryptor{
		SecretKey: secretKey,
	}
	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return encryptor, err
	}
	encryptor.block = block

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return encryptor, err
	}
	encryptor.aesGCM = aesGCM
	return encryptor, nil
}

// CookieEncryptor is used to read and write encrypted cookie values.
type CookieEncryptor struct {
	// SecretKey is the key used for the encryption.
	SecretKey []byte
	block     cipher.Block
	aesGCM    cipher.AEAD
}

// WriteCookie writes a cookie to the HTTP response writer.
func WriteCookie(w http.ResponseWriter, cookie http.Cookie) error {
	// Check the total length of the cookie contents. Return the ErrValueTooLong
	// error if it's more than 4096 bytes.
	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}

	// WriteCookie the cookie as normal.
	http.SetCookie(w, &cookie)

	return nil
}

// RequestHandlerContext is an implementation of the RequestContext interface for the standard library HTTP request and response writer.
type RequestHandlerContext struct {
	request      *http.Request
	w            http.ResponseWriter
	CookieMaxAge int
	CookiePath   string // optional
	CookieDomain string // optional
	// DangerouslyDisableSecureCookies creates cookies without the Secure flag. Not recommended for production.
	DangerouslyDisableSecureCookies bool
}

// ReadCookie reads a cookie from the request and decodes its value from base64.
func (ctx RequestHandlerContext) ReadCookie(name string) (string, error) {
	// Read the cookie as normal.
	cookie, err := ctx.request.Cookie(name)
	if err != nil {
		return "", err
	}

	// Decode the base64-encoded cookie value. If the cookie didn't contain a
	// valid base64-encoded value, this operation will fail, and we return an
	// ErrInvalidValue error.
	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	// Return the decoded cookie value.
	return string(value), nil
}

// WriteCookie writes a cookie to the HTTP response writer.
func (ctx RequestHandlerContext) WriteCookie(key, value string) {
	http.SetCookie(ctx.w, &http.Cookie{
		Name:     key,
		Value:    value,
		HttpOnly: true,
		Secure:   !ctx.DangerouslyDisableSecureCookies,
		Path:     ctx.CookiePath,
		Domain:   ctx.CookieDomain,
		MaxAge:   ctx.CookieMaxAge,
	})
}

// ReadCookie reads a cookie from the request and decodes its value from base64.
func ReadCookie(r CookieRequest, name string) (string, error) {
	// Read the cookie as normal.
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	// Decode the base64-encoded cookie value. If the cookie didn't contain a
	// valid base64-encoded value, this operation will fail, and we return an
	// ErrInvalidValue error.
	value, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		return "", ErrInvalidValue
	}

	// Return the decoded cookie value.
	return string(value), nil
}

// WriteSigned writes a signed cookie to the HTTP response writer.
func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	// Calculate a HMAC signature of the cookie name and value, using SHA256 and
	// a secret key (which we will create in a moment).
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)

	// Prepend the cookie value with the HMAC signature.
	cookie.Value = string(signature) + cookie.Value

	// Call our WriteCookie() helper to base64-encode the new cookie value and write
	// the cookie.
	return WriteCookie(w, cookie)
}

// ReadSigned reads a signed cookie value from the request.
func ReadSigned(r CookieRequest, name string, secretKey []byte) (string, error) {
	// Read in the signed value from the cookie. This should be in the format
	// "{signature}{original value}".
	signedValue, err := ReadCookie(r, name)
	if err != nil {
		return "", err
	}

	// A SHA256 HMAC signature has a fixed length of 32 bytes. To avoid a potential
	// 'index out of range' panic in the next step, we need to check sure that the
	// length of the signed cookie value is at least this long. We'll use the
	// sha256.Size constant here, rather than 32, just because it makes our code
	// a bit more understandable at a glance.
	if len(signedValue) < sha256.Size {
		return "", ErrInvalidValue
	}

	// Split apart the signature and original cookie value.
	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]

	// Recalculate the HMAC signature of the cookie name and original value.
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	// Check that the recalculated signature matches the signature we received
	// in the cookie. If they match, we can be confident that the cookie name
	// and value haven't been edited by the client.
	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", ErrInvalidValue
	}

	// Return the original cookie value.
	return value, nil
}

// EncryptCookieValue encrypts a cookie value using AES GCM encryption.
func (s CookieEncryptor) EncryptCookieValue(name, value string) (string, error) {
	// Create a unique nonce containing 12 random bytes.
	nonce := rand.GenerateRandomKey(s.aesGCM.NonceSize())

	// Prepare the plaintext input for encryption. Because we want to
	// authenticate the cookie name as well as the value, we make this plaintext
	// in the format "{cookie name}:{cookie value}". We use the : character as a
	// separator because it is an invalid character for cookie names and
	// therefore shouldn't appear in them.
	plaintext := fmt.Sprintf("%s:%s", name, value)

	// Encrypt the data using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the encrypted data will be appended to the nonce — meaning
	// that the returned encryptedValue variable will be in the format
	// "{nonce}{encrypted plaintext data}".
	encryptedValue := s.aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	encodedValue := base64.URLEncoding.EncodeToString(encryptedValue)

	// Check the total length of the cookie contents. Return the ErrValueTooLong
	// error if it's more than 4096 bytes.
	if len(encodedValue) > 4096 {
		return "", ErrValueTooLong
	}

	return encodedValue, nil
}

// WriteEncrypted writes an encrypted cookie to the HTTP response writer.
func (s CookieEncryptor) WriteEncrypted(w http.ResponseWriter, cookie http.Cookie) error {
	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(s.SecretKey)
	if err != nil {
		return err
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Create a unique nonce containing 12 random bytes.
	nonce := rand.GenerateRandomKey(aesGCM.NonceSize())

	// Prepare the plaintext input for encryption. Because we want to
	// authenticate the cookie name as well as the value, we make this plaintext
	// in the format "{cookie name}:{cookie value}". We use the : character as a
	// separator because it is an invalid character for cookie names and
	// therefore shouldn't appear in them.
	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	// Encrypt the data using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the encrypted data will be appended to the nonce — meaning
	// that the returned encryptedValue variable will be in the format
	// "{nonce}{encrypted plaintext data}".
	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Set the cookie value to the encryptedValue.
	cookie.Value = string(encryptedValue)

	// WriteCookie the cookie as normal.
	return WriteCookie(w, cookie)
}

// ReadEncrypted reads an encrypted cookie value from the request.
func (s CookieEncryptor) ReadEncrypted(r CookieRequest, name string) (string, error) {
	// Read the encrypted value from the cookie as normal.
	encryptedValue, err := ReadCookie(r, name)
	if err != nil {
		return "", err
	}

	// Get the nonce size.
	nonceSize := s.aesGCM.NonceSize()

	// To avoid a potential 'index out of range' panic in the next step, we
	// check that the length of the encrypted value is at least the nonce
	// size.
	if len(encryptedValue) < nonceSize {
		return "", ErrInvalidValue
	}

	// Split apart the nonce from the actual encrypted data.
	nonce := encryptedValue[:nonceSize]
	ciphertext := encryptedValue[nonceSize:]

	// Use aesGCM.Open() to decrypt and authenticate the data. If this fails,
	// return a ErrInvalidValue error.
	plaintext, err := s.aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", ErrInvalidValue
	}

	// The plaintext value is in the format "{cookie name}:{cookie value}". We
	// use strings.Cut() to split it on the first ":" character.
	expectedName, value, ok := strings.Cut(string(plaintext), ":")
	if !ok {
		return "", ErrInvalidValue
	}

	// Check that the cookie name is the expected one and hasn't been changed.
	if expectedName != name {
		return "", ErrInvalidValue
	}

	// Return the plaintext cookie value.
	return value, nil
}

// ReadEncryptedCookie reads an encrypted cookie value from the standard library request.
func (s CookieEncryptor) ReadEncryptedCookie(req *http.Request, name string) (string, error) {
	// Read the cookie as normal.
	cookie, err := req.Cookie(name)
	if err != nil {
		return "", err
	}

	// Decode the base64-encoded cookie value. If the cookie didn't contain a
	// valid base64-encoded value, this operation will fail, and we return an
	// ErrInvalidValue error.
	encryptedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	// Get the nonce size.
	nonceSize := s.aesGCM.NonceSize()

	// To avoid a potential 'index out of range' panic in the next step, we
	// check that the length of the encrypted value is at least the nonce
	// size.
	if len(encryptedValue) < nonceSize {
		return "", ErrInvalidValue
	}

	// Split apart the nonce from the actual encrypted data.
	nonce := encryptedValue[:nonceSize]
	ciphertext := encryptedValue[nonceSize:]

	// Use aesGCM.Open() to decrypt and authenticate the data. If this fails,
	// return a ErrInvalidValue error.
	plaintext, err := s.aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrInvalidValue
	}

	// The plaintext value is in the format "{cookie name}:{cookie value}". We
	// use strings.Cut() to split it on the first ":" character.
	expectedName, value, ok := strings.Cut(string(plaintext), ":")
	if !ok {
		return "", ErrInvalidValue
	}

	// Check that the cookie name is the expected one and hasn't been changed.
	if expectedName != name {
		return "", ErrInvalidValue
	}

	// Return the plaintext cookie value.
	return value, nil
}
