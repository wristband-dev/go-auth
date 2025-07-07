package cookies

import (
	"net/http"
)

type CookieRequest interface {
	Cookie(name string) (string, error)
}

type StdRequest struct {
	*http.Request
}

func StandardRequest(req *http.Request) *StdRequest {
	return &StdRequest{Request: req}
}

func (req *StdRequest) Cookie(name string) (string, error) {
	// Read the cookie as normal.
	cookie, err := req.Request.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
