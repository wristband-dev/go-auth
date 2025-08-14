package goauth

import (
	"encoding/json"
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
	}
)

const (
	// LoginStateCookiePrefix is the prefix used for the name of the cookie used to store the login metadata.
	LoginStateCookiePrefix = "wb-login#"
)

// Cookie handling functions

func loginStateCookieName(stateStr string) string {
	return LoginStateCookiePrefix + stateStr
}

// GetLoginStateCookie retrieves the login state from a cookie in the request and decrypts it using the CookieEncryption provided.
func GetLoginStateCookie(cookieEncryption CookieEncryption, q QueryValueResolver, req cookies.CookieRequest) (LoginState, error) {
	var s LoginState
	if q == nil || !q.Has("state") {
		return s, InvalidCallbackQueryParameterError("state")
	}
	//	fmt.Printf("\n%s\n", q.(url.Values).Encode()) // Ensure q is url.Values for Has and Get methods

	stateKey := q.Get("state")
	stateJSON, err := cookieEncryption.ReadEncrypted(req, loginStateCookieName(stateKey))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(stateJSON), &s); err != nil {
		return s, err
	}
	s.StateCookieKey = strings.TrimPrefix(s.StateCookieKey, LoginStateCookiePrefix)
	return s, nil
}
