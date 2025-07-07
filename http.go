package go_auth

import (
	"net/http"

	"github.com/wristband-dev/go-auth/cookies"
)

type (
	CookieCrypto interface {
		EncryptCookieValue(name, value string) (string, error)
	}

	// HttpContext represents the context of an HTTP request and response.
	// Web frameworks not based on the standard library should implement this interface to use this package.
	HttpContext interface {
		// Query returns a QueryValueResolver that can be used to access query parameters of the request.
		Query() QueryValueResolver
		// CookieRequest returns a CookieRequest interface for reading cookies.
		CookieRequest() cookies.CookieRequest
		// WriteCookie writes a cookie to the HTTP response.
		WriteCookie(name, value string) error
		// ClearCookie clears a cookie from the HTTP response.
		ClearCookie(name string)
	}
)

type StandardHttp struct {
	req              *http.Request
	res              http.ResponseWriter
	cookieOpts       CookieOptions
	cookieEncryption CookieEncryption
}

func (std *StandardHttp) Query() QueryValueResolver {
	return std.req.URL.Query()
}

func (std *StandardHttp) WriteCookie(name, value string) error {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		Path:     std.cookieOpts.Path,
		Domain:   std.cookieOpts.Domain,
		MaxAge:   std.cookieOpts.MaxAge,
	}

	return cookies.WriteCookie(std.res, cookie)
}

func (std *StandardHttp) CookieRequest() cookies.CookieRequest {
	return cookies.StandardRequest(std.req)
}

func (std *StandardHttp) ClearCookie(name string) {
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
