package goauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWithSessionContext_And_SessionFromContext(t *testing.T) {
	session := &Session{
		AccessToken: "tok-123",
		UserInfo:    UserInfoResponse{Sub: "user-1"},
	}

	ctx := WithSessionContext(context.Background(), session)
	got, ok := SessionFromContext(ctx)

	if !ok {
		t.Fatal("Expected session from context, got nil")
	}
	if got.AccessToken != "tok-123" {
		t.Errorf("Expected AccessToken %q, got %q", "tok-123", got.AccessToken)
	}
	if got.UserInfo.Sub != "user-1" {
		t.Errorf("Expected Sub %q, got %q", "user-1", got.UserInfo.Sub)
	}
}

func TestSessionFromContext_Missing(t *testing.T) {
	_, ok := SessionFromContext(context.Background())
	if ok {
		t.Error("Expected nil session from empty context")
	}
}

func TestRequireAuthentication_NoSession(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.getErr = fmt.Errorf("no session")

	app := WristbandApp{SessionManager: sessionManager}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, res.Code)
	}
	if nextCalled {
		t.Error("Next handler should not be called when unauthenticated")
	}
}

func TestCacheControlMiddleware(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	res := httptest.NewRecorder()

	CacheControlMiddleware(next).ServeHTTP(res, req)

	if !nextCalled {
		t.Error("Next handler should be called")
	}
	if res.Header().Get("Cache-Control") != "no-cache, no-store" {
		t.Errorf("Expected Cache-Control header, got %q", res.Header().Get("Cache-Control"))
	}
	if res.Header().Get("Pragma") != "no-cache" {
		t.Errorf("Expected Pragma header, got %q", res.Header().Get("Pragma"))
	}
}

func TestRefreshTokenIfExpired_NoSession(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.getErr = fmt.Errorf("no session")

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
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(sessionManager)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if nextCalled {
		t.Error("Next handler should not be called when no session exists")
	}
}

func TestRefreshTokenIfExpired_TokenStillValid(t *testing.T) {
	sessionManager := newMockSessionManager()
	session := &Session{
		AccessToken: "valid-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	sessionManager.sessions["test-session"] = session

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
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(sessionManager)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if !nextCalled {
		t.Error("Next handler should be called when token is still valid")
	}
	if res.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, res.Code)
	}
}

func TestRefreshTokenIfExpired_TokenExpired_RefreshSuccess(t *testing.T) {
	// Mock token endpoint that returns a new token
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	sessionManager := newMockSessionManager()
	session := &Session{
		AccessToken:  "expired-token",
		RefreshToken: "old-refresh-token",
		ExpiresAt:    time.Now().Add(-time.Hour), // expired
	}
	sessionManager.sessions["test-session"] = session

	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},

		httpClient: tokenServer.Client(),
	}
	auth, _ := authConfig.WristbandAuth()
	// Override tokenURL to point to test server
	auth.tokenURL = tokenServer.URL
	app := auth.NewApp(sessionManager)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if !nextCalled {
		t.Error("Next handler should be called after successful refresh")
	}

	// Verify session was updated
	updated := sessionManager.sessions["test-session"]
	if updated.AccessToken != "new-access-token" {
		t.Errorf("Expected new access token, got %q", updated.AccessToken)
	}
	if updated.RefreshToken != "new-refresh-token" {
		t.Errorf("Expected new refresh token, got %q", updated.RefreshToken)
	}
}

func TestRefreshTokenIfExpired_TokenExpired_RefreshFails(t *testing.T) {
	// Mock token endpoint that returns an error
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	sessionManager := newMockSessionManager()
	session := &Session{
		AccessToken:  "expired-token",
		RefreshToken: "invalid-refresh-token",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	sessionManager.sessions["test-session"] = session

	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
		httpClient: tokenServer.Client(),
	}
	auth, _ := authConfig.WristbandAuth()
	auth.tokenURL = tokenServer.URL
	app := auth.NewApp(sessionManager)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if nextCalled {
		t.Error("Next handler should not be called when refresh fails")
	}
	if res.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d, got %d", http.StatusFound, res.Code)
	}
	location := res.Header().Get("Location")
	if location == "" {
		t.Error("Expected redirect Location header")
	}

	// Session should be cleared
	if _, exists := sessionManager.sessions["test-session"]; exists {
		t.Error("Session should have been cleared after failed refresh")
	}
}

func TestRefreshTokenIfExpired_StoreSessionError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := TokenResponse{
			AccessToken: "new-access-token",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	sessionManager := newMockSessionManager()
	session := &Session{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	sessionManager.sessions["test-session"] = session
	sessionManager.storeErr = fmt.Errorf("store failed")

	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
		httpClient: tokenServer.Client(),
	}
	auth, _ := authConfig.WristbandAuth()
	auth.tokenURL = tokenServer.URL

	app := auth.NewApp(sessionManager)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	res := httptest.NewRecorder()

	app.RequireAuthentication(next).ServeHTTP(res, req)

	if nextCalled {
		t.Error("Next handler should not be called when store fails")
	}
	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}
}
