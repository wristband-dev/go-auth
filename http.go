package goauth

import (
	"net/http"

	"github.com/wristband-dev/go-auth/cookies"
)

type (
	// HTTPRequest represents an HTTP request.
	HTTPRequest interface {
		// Query returns a QueryValueResolver that can be used to access query parameters of the request.
		Query() QueryValueResolver
		// Host returns the host of the request.
		Host() string
	}

	// HTTPContext represents the context of an HTTP request and response.
	// Web frameworks not based on the standard library should implement this interface to use this package.
	HTTPContext interface {
		// Query returns a QueryValueResolver that can be used to access query parameters of the request.
		Query() QueryValueResolver
		// CookieRequest returns a CookieRequest interface for reading cookies.
		CookieRequest() cookies.CookieRequest
		// WriteCookie writes a cookie to the HTTP response.
		WriteCookie(name, value string) error
		// ClearCookie clears a cookie from the HTTP response.
		ClearCookie(name string)
		// Host returns the host of the request.
		Host() string
	}
)

// StandardHTTP implements the HTTPContext interface for standard library HTTP requests and responses.
type StandardHTTP struct {
	req              *http.Request
	res              http.ResponseWriter
	cookieOpts       CookieOptions
	cookieEncryption CookieEncryption
}

// Query returns a QueryValueResolver from the *http.Request.
func (std *StandardHTTP) Query() QueryValueResolver {
	return std.req.URL.Query()
}

// Host returns the host of the HTTP request.
func (std *StandardHTTP) Host() string {
	return std.req.URL.Host
}

// WriteCookie writes a cookie to the HTTP response using http.Cookie.
func (std *StandardHTTP) WriteCookie(name, value string) error {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   !std.cookieOpts.DangerouslyDisableSecureCookies,
		Path:     std.cookieOpts.Path,
		Domain:   std.cookieOpts.Domain,
		MaxAge:   std.cookieOpts.MaxAge,
	}

	return cookies.WriteCookie(std.res, cookie)
}

// CookieRequest wraps the *http.Request to provide a CookieRequest interface for reading cookies.
func (std *StandardHTTP) CookieRequest() cookies.CookieRequest {
	return cookies.StandardRequest(std.req)
}

// ClearCookie clears a cookie from the HTTP response by setting its MaxAge to -1 and value to an empty string.
func (std *StandardHTTP) ClearCookie(name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		Path:     std.cookieOpts.Path,
		Domain:   std.cookieOpts.Domain,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(std.res, cookie)
}
