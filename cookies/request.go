package cookies

import (
	"net/http"
)

// CookieRequest defines an interface for retrieving cookie values from an http request.
type CookieRequest interface {
	// Cookie retrieves the value of a cookie by its name.
	Cookie(name string) (string, error)
	// Cookies retrieves all cookie names from the request.
	Cookies() []string
}

// StdRequest wraps an *http.Request to provide a CookieRequest interface.
type StdRequest struct {
	*http.Request
}

// StandardRequest creates a new StdRequest from an *http.Request.
func StandardRequest(req *http.Request) *StdRequest {
	return &StdRequest{Request: req}
}

// Cookie retrieves the value of a cookie by its name from the request.
func (req *StdRequest) Cookie(name string) (string, error) {
	// Read the cookie as normal.
	cookie, err := req.Request.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// Cookies retrieves all cookie names from the request.
func (req *StdRequest) Cookies() []string {
	cookies := req.Request.Cookies()
	names := make([]string, len(cookies))
	for i, cookie := range cookies {
		names[i] = cookie.Name
	}
	return names
}
