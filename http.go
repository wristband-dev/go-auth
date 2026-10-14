package goauth

import (
	"net/http"
	"strings"

	"github.com/wristband-dev/go-auth/cookies"
)

type (
	// RequestURI represents an HTTP request's URI.
	RequestURI interface {
		// Query returns a QueryValueResolver that can be used to access query parameters of the request.
		Query() QueryValueResolver
		// Host returns the host of the request.
		Host() string
	}

	// RequestScheme is optionally implemented by an HTTPContext to report the scheme ("http" or "https") of the
	// request. The SDK uses it to validate return URLs. StandardHTTP implements it. When an HTTPContext doesn't
	// implement it, the SDK assumes "https".
	RequestScheme interface {
		// Scheme returns the scheme of the request.
		Scheme() string
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

// NewStandardHttpContext returns the HTTPContext for the standard library http types.
func (auth WristbandAuth) NewStandardHttpContext(w http.ResponseWriter, r *http.Request) *StandardHTTP {
	return &StandardHTTP{
		req:              r,
		res:              w,
		cookieOpts:       auth.defaultCookieOptions(),
		cookieEncryption: auth.cookieEncryption,
	}
}

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
	return std.req.Host
}

// Scheme returns the scheme of the HTTP request. It uses the X-Forwarded-Proto header set by a reverse proxy when
// present, and otherwise whether the request was received over TLS.
func (std *StandardHTTP) Scheme() string {
	if forwardedProto := std.req.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		if strings.EqualFold(strings.TrimSpace(strings.Split(forwardedProto, ",")[0]), "https") {
			return "https"
		}
		return "http"
	}
	if std.req.TLS != nil {
		return "https"
	}
	return "http"
}

// WriteCookie writes a cookie to the HTTP response using http.Cookie.
func (std *StandardHTTP) WriteCookie(name, value string) error {
	return std.WriteCookieWithDomain(name, value, std.cookieOpts.Domain)
}

// WriteCookieWithDomain writes a cookie on the given domain to the HTTP response using http.Cookie.
func (std *StandardHTTP) WriteCookieWithDomain(name, value, domain string) error {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   !std.cookieOpts.DangerouslyDisableSecureCookies,
		Path:     std.cookieOpts.Path,
		Domain:   domain,
		MaxAge:   std.cookieOpts.MaxAge,
		SameSite: std.cookieOpts.SameSite,
	}

	return cookies.WriteCookie(std.res, cookie)
}

// CookieRequest wraps the *http.Request to provide a CookieRequest interface for reading cookies.
func (std *StandardHTTP) CookieRequest() cookies.CookieRequest {
	return cookies.StandardRequest(std.req)
}

// ClearCookie clears a cookie from the HTTP response by setting its MaxAge to -1 and value to an empty string.
func (std *StandardHTTP) ClearCookie(name string) {
	std.ClearCookieWithDomain(name, std.cookieOpts.Domain)
}

// ClearCookieWithDomain clears a cookie on the given domain from the HTTP response.
func (std *StandardHTTP) ClearCookieWithDomain(name, domain string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		HttpOnly: true,
		Secure:   !std.cookieOpts.DangerouslyDisableSecureCookies,
		Path:     std.cookieOpts.Path,
		Domain:   domain,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(std.res, cookie)
}
