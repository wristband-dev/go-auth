package go_auth

import (
	"encoding/json"
	"strings"

	"github.com/wristband-dev/go-auth/cookies"
)

type (

	// CookieEncryption is used to read and write encrypted cookie values.
	CookieEncryption interface {
		ReadEncrypted(r cookies.CookieRequest, name string) (string, error)
		EncryptCookieValue(name, value string) (string, error)
	}

	CookieOptions struct {
		Domain string
		Path   string
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

func GetLoginStateCookie(cookieEncryption CookieEncryption, q QueryValueResolver, req cookies.CookieRequest) (LoginState, error) {
	var s LoginState
	if q == nil || !q.Has("state") {
		return s, InvalidCallbackQueryParameterError("state")
	}

	stateKey := q.Get("state")
	stateJson, err := cookieEncryption.ReadEncrypted(req, stateKey)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(stateJson), &s); err != nil {
		return s, err
	}
	s.StateCookieKey = strings.TrimPrefix(s.StateCookieKey, LoginStateCookiePrefix)
	return s, nil
}
