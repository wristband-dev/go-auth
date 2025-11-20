package goauth

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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
	}
)

const (
	// LoginStateCookiePrefix is the prefix used for the name of the cookie used to store the login metadata.
	LoginStateCookiePrefix = "login#"
)

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
