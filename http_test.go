package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewStandardHttpContext(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		DangerouslyDisableSecureCookies:  true,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?foo=bar", nil)
	res := httptest.NewRecorder()

	ctx := auth.NewStandardHttpContext(res, req)
	if ctx == nil {
		t.Fatal("NewStandardHttpContext returned nil")
	}
	if ctx.req != req {
		t.Error("Request not set correctly")
	}
	if ctx.res != res {
		t.Error("ResponseWriter not set correctly")
	}
}

func TestStandardHTTP_Host(t *testing.T) {
	req := httptest.NewRequest("GET", "http://tenant1.example.com/test", nil)
	res := httptest.NewRecorder()

	std := &StandardHTTP{req: req, res: res}

	if std.Host() != "tenant1.example.com" {
		t.Errorf("Expected host %q, got %q", "tenant1.example.com", std.Host())
	}
}

func TestStandardHTTP_Query(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test?code=abc&state=xyz", nil)
	res := httptest.NewRecorder()

	std := &StandardHTTP{req: req, res: res}
	q := std.Query()

	if q.Get("code") != "abc" {
		t.Errorf("Expected code=abc, got %q", q.Get("code"))
	}
	if q.Get("state") != "xyz" {
		t.Errorf("Expected state=xyz, got %q", q.Get("state"))
	}
}

func TestStandardHTTP_WriteCookie(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := httptest.NewRecorder()

	std := &StandardHTTP{
		req: req,
		res: res,
		cookieOpts: CookieOptions{
			Domain:   "example.com",
			Path:     "/app",
			MaxAge:   1800,
			SameSite: http.SameSiteLaxMode,
		},
	}

	err := std.WriteCookie("session-id", "abc123")
	if err != nil {
		t.Fatalf("WriteCookie returned error: %v", err)
	}

	result := res.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != "session-id" {
		t.Errorf("Expected name %q, got %q", "session-id", c.Name)
	}
	if c.Value != "abc123" {
		t.Errorf("Expected value %q, got %q", "abc123", c.Value)
	}
	if !c.HttpOnly {
		t.Error("Expected HttpOnly")
	}
	if !c.Secure {
		t.Error("Expected Secure by default")
	}
	if c.Domain != "example.com" {
		t.Errorf("Expected domain %q, got %q", "example.com", c.Domain)
	}
	if c.Path != "/app" {
		t.Errorf("Expected path %q, got %q", "/app", c.Path)
	}
	if c.MaxAge != 1800 {
		t.Errorf("Expected MaxAge 1800, got %d", c.MaxAge)
	}
}

func TestStandardHTTP_WriteCookie_InsecureMode(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := httptest.NewRecorder()

	std := &StandardHTTP{
		req: req,
		res: res,
		cookieOpts: CookieOptions{
			DangerouslyDisableSecureCookies: true,
		},
	}

	err := std.WriteCookie("test", "val")
	if err != nil {
		t.Fatalf("WriteCookie returned error: %v", err)
	}

	c := res.Result().Cookies()[0]
	if c.Secure {
		t.Error("Expected Secure=false with DangerouslyDisableSecureCookies")
	}
}

func TestStandardHTTP_CookieRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: "val"})
	res := httptest.NewRecorder()

	std := &StandardHTTP{req: req, res: res}
	cookieReq := std.CookieRequest()

	val, err := cookieReq.Cookie("sess")
	if err != nil {
		t.Fatalf("Cookie returned error: %v", err)
	}
	if val != "val" {
		t.Errorf("Expected %q, got %q", "val", val)
	}
}

func TestStandardHTTP_ClearCookie(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	res := httptest.NewRecorder()

	std := &StandardHTTP{
		req: req,
		res: res,
		cookieOpts: CookieOptions{
			Domain: "example.com",
			Path:   "/",
		},
	}

	std.ClearCookie("old-session")

	result := res.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != "old-session" {
		t.Errorf("Expected name %q, got %q", "old-session", c.Name)
	}
	if c.Value != "" {
		t.Errorf("Expected empty value, got %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("Expected MaxAge -1, got %d", c.MaxAge)
	}
	if c.Domain != "example.com" {
		t.Errorf("Expected domain %q, got %q", "example.com", c.Domain)
	}
}
