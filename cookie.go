package goauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wristband-dev/go-auth/cookies"
)

type (
	// CookieEncryption is used to read and write encrypted cookie values.
	CookieEncryption interface {
		// ReadEncrypted reads an encrypted cookie value by name from the request.
		ReadEncrypted(r cookies.CookieRequest, name string) (string, error)
		// EncryptCookieValue encrypts a cookie value with the given name.
		EncryptCookieValue(name, value string) (string, error)
	}

	// DomainCookieWriter is optionally implemented by an HTTPContext that can write and clear cookies on a specific
	// domain. The SDK uses it to set the login state cookie on the root domain when application-level authorization
	// requests are enabled and tenant subdomains are in use, so that a login that starts on the root domain can
	// finish on a tenant subdomain. StandardHTTP implements it. HTTPContext implementations that don't implement it
	// fall back to WriteCookie and ClearCookie.
	DomainCookieWriter interface {
		// WriteCookieWithDomain writes a cookie to the HTTP response on the given domain.
		WriteCookieWithDomain(name, value, domain string) error
		// ClearCookieWithDomain clears a cookie on the given domain from the HTTP response.
		ClearCookieWithDomain(name, domain string)
	}

	// CookieOptions holds optional configuration for cookies that are written to the HTTP response.
	// Fields are a subset of http.Cookie fields.
	CookieOptions struct {
		Domain string
		Path   string
		// MaxAge=0 means no Max-Age attribute specified and the cookie will be
		// deleted after the browser session ends.
		// MaxAge<0 means delete cookie immediately.
		// MaxAge>0 means Max-Age attribute present and given in seconds.
		MaxAge int
		// DangerouslyDisableSecureCookies creates cookies without the Secure flag. Not recommended for production.
		DangerouslyDisableSecureCookies bool
		SameSite                        http.SameSite
	}
)

const (
	// LoginStateCookiePrefix is the prefix used for the name of the cookie used to store the login metadata.
	LoginStateCookiePrefix = "login#"

	// loginStateMaxAge is the lifetime of the login state, which matches the login state cookie's Max-Age.
	loginStateMaxAge = time.Hour
	// loginStateClockSkew is the clock skew tolerance applied when checking the login state's lifetime.
	loginStateClockSkew = time.Minute
)

// writeCookie writes a cookie on the given domain when the HTTPContext supports it, and host-only otherwise.
func writeCookie(httpCtx HTTPContext, name, value, domain string) error {
	if writer, ok := httpCtx.(DomainCookieWriter); ok && domain != "" {
		return writer.WriteCookieWithDomain(name, value, domain)
	}
	return httpCtx.WriteCookie(name, value)
}

// clearCookie clears a cookie on the given domain when the HTTPContext supports it, and host-only otherwise.
func clearCookie(httpCtx HTTPContext, name, domain string) {
	if writer, ok := httpCtx.(DomainCookieWriter); ok && domain != "" {
		writer.ClearCookieWithDomain(name, domain)
		return
	}
	httpCtx.ClearCookie(name)
}

// isLoginStateExpired reports whether a login state was created longer ago than its lifetime, or in the future,
// allowing for some clock skew.
func isLoginStateExpired(state LoginState, now time.Time) bool {
	createdAt := time.UnixMilli(state.CreatedAt)
	return now.Sub(createdAt) > loginStateMaxAge+loginStateClockSkew || createdAt.Sub(now) > loginStateClockSkew
}

// Cookie handling functions

func loginStateCookieName(stateStr string, timestamp int64) string {
	return fmt.Sprintf("%s%s#%d", LoginStateCookiePrefix, stateStr, timestamp)
}

// parseLoginStateCookieName extracts the state value and timestamp from a login state cookie name.
func parseLoginStateCookieName(cookieName string) (state string, timestamp int64, err error) {
	// Remove the prefix
	if !strings.HasPrefix(cookieName, LoginStateCookiePrefix) {
		return "", 0, fmt.Errorf("invalid login state cookie name: missing prefix")
	}

	remainder := strings.TrimPrefix(cookieName, LoginStateCookiePrefix)

	// Split by '#' to get state and timestamp
	parts := strings.Split(remainder, "#")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid login state cookie name format")
	}

	state = parts[0]
	timestamp, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("invalid timestamp in cookie name: %w", err)
	}

	return state, timestamp, nil
}

// GetLoginStateCookie retrieves the login state from a cookie in the request and decrypts it using the CookieEncryption provided.
func GetLoginStateCookie(cookieEncryption CookieEncryption, reqCtx HTTPContext) (LoginState, error) {
	q := reqCtx.Query()
	var s LoginState
	if q == nil || !q.Has("state") {
		return s, InvalidCallbackQueryParameterError("state")
	}

	stateKey := q.Get("state")

	// Find the cookie that matches the state key from query parameter
	allCookieNames := reqCtx.CookieRequest().Cookies()
	var matchingCookieName string

	for _, cookieName := range allCookieNames {
		if !strings.HasPrefix(cookieName, LoginStateCookiePrefix) {
			continue
		}
		state, _, err := parseLoginStateCookieName(cookieName)
		if err != nil {
			continue
		}
		if state == stateKey {
			matchingCookieName = cookieName
			break
		}
	}

	if matchingCookieName == "" {
		return s, ErrorNoLoginState
	}

	stateJSON, err := cookieEncryption.ReadEncrypted(reqCtx.CookieRequest(), matchingCookieName)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(stateJSON), &s); err != nil {
		return s, err
	}
	s.StateCookieKey = strings.TrimPrefix(s.StateCookieKey, LoginStateCookiePrefix)
	return s, nil
}
