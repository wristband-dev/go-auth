package goauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression: RequireAuthentication must re-store the session on every authenticated
// request, not only when the access token needed refreshing. Without this the session
// cookie is never re-issued while the user is active, so its expiration never moves
// forward (no rolling session expiration) and the session expires mid-use.
func TestRequireAuthentication_StoresSessionWhenTokenStillValid(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.sessions["test-session"] = &Session{
		AccessToken: "still-valid",
		// Well beyond the expiration buffer, so no token refresh is triggered.
		ExpiresAt: time.Now().Add(1 * time.Hour).UnixMilli(),
	}

	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to build WristbandAuth: %v", err)
	}

	app := WristbandApp{WristbandAuth: auth, SessionManager: sessionManager}

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if !nextCalled {
		t.Error("Expected the next handler to be called for a valid session")
	}
	if sessionManager.storeCalls != 1 {
		t.Errorf("Expected the session to be re-stored once for rolling expiration, got %d calls",
			sessionManager.storeCalls)
	}
}

// A failure to persist the refreshed session must surface rather than silently continuing.
func TestRequireAuthentication_StoreSessionErrorOnValidToken(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.sessions["test-session"] = &Session{
		AccessToken: "still-valid",
		ExpiresAt:   time.Now().Add(1 * time.Hour).UnixMilli(),
	}
	sessionManager.storeErr = http.ErrNotSupported

	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to build WristbandAuth: %v", err)
	}

	app := WristbandApp{WristbandAuth: auth, SessionManager: sessionManager}

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if nextCalled {
		t.Error("Expected the next handler not to be called when the session could not be stored")
	}
	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}
}

// Regression: when logoutHost fails for a reason other than "no tenant resolvable" (for
// example the tenant custom domain validation call failing), LogoutURL must return the
// error. Previously it fell through and built "https:///api/v1/logout?...", an empty-host
// URL that browsers resolve against the current origin -- producing a 404 against the
// application instead of reaching Wristband.
func TestLogoutURL_DoesNotBuildEmptyHostURLOnValidationFailure(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 500, body: "Internal Server Error"})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "custom.acme.com")

	logoutURL, err := auth.LogoutURL(ctx, NewLogoutConfig())
	if err == nil {
		t.Fatalf("Expected an error, got URL %q", logoutURL)
	}
	if logoutURL != "" {
		t.Errorf("Expected an empty URL on failure, got %q", logoutURL)
	}
}
