package goauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wristband-dev/go-auth/cookies"
)

// Mock implementations for testing

type mockSessionManager struct {
	sessions map[string]*Session
	storeErr error
	getErr   error
	clearErr error
}

func newMockSessionManager() *mockSessionManager {
	return &mockSessionManager{
		sessions: make(map[string]*Session),
	}
}

func (m *mockSessionManager) StoreSession(ctx context.Context, w http.ResponseWriter, r *http.Request, session *Session) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.sessions["test-session"] = session
	return nil
}

func (m *mockSessionManager) GetSession(ctx context.Context, r *http.Request) (*Session, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if session, exists := m.sessions["test-session"]; exists {
		return session, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (m *mockSessionManager) ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if m.clearErr != nil {
		return m.clearErr
	}
	delete(m.sessions, "test-session")
	return nil
}

type mockHTTPContext struct {
	queryValues      url.Values
	host             string
	writtenCookies   map[string]string
	clearedCookies   []string
	cookieRequest    cookies.CookieRequest
	writeCookieError error
}

func newMockHTTPContext() *mockHTTPContext {
	mockCookieReq := newMockCookieRequest()
	return &mockHTTPContext{
		queryValues:    make(url.Values),
		writtenCookies: make(map[string]string),
		clearedCookies: make([]string, 0),
		cookieRequest:  mockCookieReq,
	}
}

func (m *mockHTTPContext) Query() QueryValueResolver {
	return m.queryValues
}

func (m *mockHTTPContext) Host() string {
	return m.host
}

func (m *mockHTTPContext) CookieRequest() cookies.CookieRequest {
	return m.cookieRequest
}

func (m *mockHTTPContext) WriteCookie(name, value string) error {
	if m.writeCookieError != nil {
		return m.writeCookieError
	}
	m.writtenCookies[name] = value
	return nil
}

func (m *mockHTTPContext) ClearCookie(name string) {
	m.clearedCookies = append(m.clearedCookies, name)
}

type mockCookieRequest struct {
	cookies map[string]string
}

func newMockCookieRequest() *mockCookieRequest {
	return &mockCookieRequest{
		cookies: make(map[string]string),
	}
}

func (m *mockCookieRequest) Cookie(name string) (string, error) {
	if val, exists := m.cookies[name]; exists {
		return val, nil
	}
	return "", fmt.Errorf("cookie not found: %s", name)
}

func (m *mockCookieRequest) Cookies() []string {
	names := make([]string, 0, len(m.cookies))
	for name := range m.cookies {
		names = append(names, name)
	}
	return names
}

type mockCookieEncryption struct {
	encryptedValues map[string]string
	readErr         error
	encryptErr      error
}

func newMockCookieEncryption() *mockCookieEncryption {
	return &mockCookieEncryption{
		encryptedValues: make(map[string]string),
	}
}

func (m *mockCookieEncryption) ReadEncrypted(r cookies.CookieRequest, name string) (string, error) {
	if m.readErr != nil {
		return "", m.readErr
	}
	if val, exists := m.encryptedValues[name]; exists {
		return val, nil
	}
	return "", fmt.Errorf("cookie not found")
}

func (m *mockCookieEncryption) EncryptCookieValue(name, value string) (string, error) {
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	encrypted := "encrypted_" + value
	m.encryptedValues[name] = encrypted
	return encrypted, nil
}

// Test Session struct

func TestSession_JSONMarshaling(t *testing.T) {
	now := time.Now()
	session := &Session{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		IDToken:      "test-id-token", // Should be omitted from JSON
		ExpiresAt:    now,
		ExpiresIn:    time.Hour,
		UserInfo: UserInfoResponse{
			Sub:      "test-user",
			Email:    "test@example.com",
			Name:     "Test User",
			TenantID: "test-tenant",
			IDPName:  "test-idp",
		},
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	// Verify IDToken is omitted from JSON
	jsonStr := string(data)
	if strings.Contains(jsonStr, "test-id-token") {
		t.Error("IDToken should be omitted from JSON")
	}

	// Verify other fields are present
	if !strings.Contains(jsonStr, "test-access-token") {
		t.Error("AccessToken should be included in JSON")
	}
	if !strings.Contains(jsonStr, "test-refresh-token") {
		t.Error("RefreshToken should be included in JSON")
	}

	// Test unmarshaling
	var unmarshaled Session
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal session: %v", err)
	}

	if unmarshaled.AccessToken != session.AccessToken {
		t.Errorf("Expected AccessToken %s, got %s", session.AccessToken, unmarshaled.AccessToken)
	}
	if unmarshaled.UserInfo.Sub != session.UserInfo.Sub {
		t.Errorf("Expected UserInfo.Sub %s, got %s", session.UserInfo.Sub, unmarshaled.UserInfo.Sub)
	}
}

// Test AppInput and NewApp

func TestNewApp(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	resolver, _ := NewConfigResolver(authConfig)
	auth := WristbandAuth{
		Client: ConfidentialClient{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		configResolver: resolver,
	}

	sessionManager := newMockSessionManager()

	app := auth.NewApp(sessionManager)

	if app.SessionManager != sessionManager {
		t.Error("SessionManager not set correctly")
	}
}

// Test WristbandApp methods

func TestWristbandApp_HTTPContext(t *testing.T) {
	cookieOpts := CookieOptions{Domain: "example.com"}
	cookieEncryption := newMockCookieEncryption()

	app := WristbandApp{
		WristbandAuth: WristbandAuth{
			cookieEncryption: cookieEncryption,
			cookieOptions:    cookieOpts,
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	res := httptest.NewRecorder()

	ctx := app.HTTPContext(res, req)

	standardHTTP, ok := ctx.(*StandardHTTP)
	if !ok {
		t.Fatal("Expected StandardHTTP context")
	}

	if standardHTTP.req != req {
		t.Error("Request not set correctly in context")
	}
	if standardHTTP.res != res {
		t.Error("Response not set correctly in context")
	}
	if standardHTTP.cookieOpts.Domain != cookieOpts.Domain {
		t.Error("Cookie options not set correctly in context")
	}
}

// Test HTTP Handlers

func TestWristbandApp_LoginHandler_WithoutTenantDomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	app := WristbandApp{
		WristbandAuth: auth,
	}

	req := httptest.NewRequest("GET", "http://example.com/login", nil)
	res := httptest.NewRecorder()

	handler := app.LoginHandler()
	handler(res, req)

	if res.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, res.Code)
	}

	location := res.Header().Get("Location")
	// Without tenant in query params, RequestTenantName returns error
	// This redirects to the application login page
	if !strings.Contains(location, "test.wristband.com/login") {
		t.Errorf("Expected application login URL, got %s", location)
	}
	if !strings.Contains(location, "client_id=test-client") {
		t.Errorf("Expected client_id in URL, got %s", location)
	}

	// Verify cache headers
	if res.Header().Get("Cache-Control") != "no-cache, no-store" {
		t.Error("Cache-Control header not set correctly")
	}
	if res.Header().Get("Pragma") != "no-cache" {
		t.Error("Pragma header not set correctly")
	}
}

func TestWristbandApp_LoginHandler_WithCustomLoginPage(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:                      "https://test.wristband.com/login",
			RedirectURI:                   "http://example.com/callback",
			CustomApplicationLoginPageURL: "https://custom.example.com/login",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	app := WristbandApp{
		WristbandAuth: auth,
	}

	req := httptest.NewRequest("GET", "http://example.com/login", nil)
	res := httptest.NewRecorder()

	handler := app.LoginHandler()
	handler(res, req)

	if res.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, res.Code)
	}

	location := res.Header().Get("Location")
	// Without tenant in query params, RequestTenantName returns error
	// When custom login page is configured, it redirects there
	if !strings.Contains(location, "custom.example.com/login") {
		t.Errorf("Expected custom login page URL, got %s", location)
	}
	if !strings.Contains(location, "client_id=test-client") {
		t.Errorf("Expected client_id in URL, got %s", location)
	}
}

func TestWristbandApp_CallbackHandler_RequestError(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(newMockSessionManager())

	// Request with error query params from Wristband
	req := httptest.NewRequest("GET", "http://example.com/callback?error=access_denied&error_description=user+denied", nil)
	res := httptest.NewRecorder()

	handler := app.CallbackHandler()
	handler(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}
}

func TestWristbandApp_CallbackHandler_MissingCode(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(newMockSessionManager())

	// Request without code param
	req := httptest.NewRequest("GET", "http://example.com/callback?tenant_name=acme", nil)
	res := httptest.NewRecorder()

	handler := app.CallbackHandler()
	handler(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}
}

func TestWristbandApp_LogoutHandler_Success(t *testing.T) {
	// Mock revoke endpoint
	revokeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer revokeServer.Close()

	sessionManager := newMockSessionManager()
	session := &Session{
		RefreshToken: "test-refresh-token",
		TenantName:   "tenant1",
		UserInfo:     UserInfoResponse{Sub: "test-user"},
	}
	sessionManager.sessions["test-session"] = session

	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
		httpClient: revokeServer.Client(),
	}
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(sessionManager)

	req := httptest.NewRequest("GET", "http://example.com/logout?tenant_name=tenant1", nil)
	res := httptest.NewRecorder()

	handler := app.LogoutHandler()
	handler(res, req)

	if res.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, res.Code)
	}

	location := res.Header().Get("Location")
	if !strings.Contains(location, "logout") {
		t.Errorf("Expected redirect to logout URL, got %s", location)
	}

	// Verify session was cleared
	if _, exists := sessionManager.sessions["test-session"]; exists {
		t.Error("Session should have been cleared")
	}
}

func TestWristbandApp_LogoutHandler_NoSession(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.getErr = fmt.Errorf("no session")

	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(sessionManager)

	// With tenant_name in query, LogoutURL can build a URL even without a session
	req := httptest.NewRequest("GET", "http://example.com/logout?tenant_name=tenant1", nil)
	res := httptest.NewRecorder()

	handler := app.LogoutHandler()
	handler(res, req)

	// Should redirect to logout URL (no session to clear)
	if res.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, res.Code)
	}
}

func TestWristbandApp_LogoutHandler_ClearSessionError(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.clearErr = fmt.Errorf("clear error")
	session := &Session{
		TenantName: "tenant1",
		UserInfo:   UserInfoResponse{Sub: "test-user"},
	}
	sessionManager.sessions["test-session"] = session

	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://test.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	app := auth.NewApp(sessionManager)

	req := httptest.NewRequest("GET", "http://example.com/logout?tenant_name=tenant1", nil)
	res := httptest.NewRecorder()

	handler := app.LogoutHandler()
	handler(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}
}

func TestWristbandApp_SessionHandler_Success(t *testing.T) {
	sessionManager := newMockSessionManager()
	session := &Session{
		UserInfo: UserInfoResponse{
			Sub:      "test-user",
			Email:    "test@example.com",
			TenantID: "test-tenant-id",
		},
	}
	sessionManager.sessions["test-session"] = session

	app := WristbandApp{
		SessionManager: sessionManager,
	}

	req := httptest.NewRequest("GET", "http://example.com/session", nil)
	res := httptest.NewRecorder()

	handler := app.SessionHandler()
	handler(res, req)

	if res.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, res.Code)
	}

	if res.Header().Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be application/json")
	}

	var response SessionResponse
	err := json.Unmarshal(res.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.UserID != session.UserInfo.Sub {
		t.Errorf("Expected UserID %s, got %s", session.UserInfo.Sub, response.UserID)
	}
	if response.TenantID != session.UserInfo.TenantID {
		t.Errorf("Expected TenantID %s, got %s", session.UserInfo.TenantID, response.TenantID)
	}
	if response.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
}

func TestWristbandApp_SessionHandler_WithCustomMetadataExtractor(t *testing.T) {
	sessionManager := newMockSessionManager()
	session := &Session{
		UserInfo: UserInfoResponse{
			Sub:      "test-user-id",
			TenantID: "test-tenant-id",
			Name:     "Test User",
		},
	}
	sessionManager.sessions["test-session"] = session

	app := WristbandApp{
		SessionManager: sessionManager,
	}

	req := httptest.NewRequest("GET", "http://example.com/session", nil)
	res := httptest.NewRecorder()

	handler := app.SessionHandler(WithSessionMetadataExtractor(func(s Session) any {
		return map[string]string{
			"custom_name": s.UserInfo.Name,
			"custom_id":   s.UserInfo.Sub,
		}
	}))
	handler(res, req)

	if res.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, res.Code)
	}

	var response SessionResponse
	err := json.Unmarshal(res.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	metadata, ok := response.Metadata.(map[string]any)
	if !ok {
		t.Fatal("Metadata should be a map")
	}

	if metadata["custom_name"] != "Test User" {
		t.Errorf("Expected custom_name 'Test User', got %v", metadata["custom_name"])
	}
	if metadata["custom_id"] != "test-user-id" {
		t.Errorf("Expected custom_id 'test-user-id', got %v", metadata["custom_id"])
	}
}

func TestWristbandApp_SessionHandler_NoSession(t *testing.T) {
	sessionManager := newMockSessionManager()
	sessionManager.getErr = fmt.Errorf("no session")

	app := WristbandApp{
		SessionManager: sessionManager,
	}

	req := httptest.NewRequest("GET", "http://example.com/session", nil)
	res := httptest.NewRecorder()

	handler := app.SessionHandler()
	handler(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, res.Code)
	}

	if !strings.Contains(res.Body.String(), "Unauthorized access") {
		t.Error("Response should contain unauthorized message")
	}
}

func TestWristbandApp_SessionHandler_MarshalError(t *testing.T) {
	sessionManager := newMockSessionManager()
	session := &Session{
		UserInfo: UserInfoResponse{
			Sub:      "test-user-id",
			TenantID: "test-tenant-id",
		},
	}
	sessionManager.sessions["test-session"] = session

	app := WristbandApp{
		SessionManager: sessionManager,
	}

	req := httptest.NewRequest("GET", "http://example.com/session", nil)
	res := httptest.NewRecorder()

	handler := app.SessionHandler(WithSessionMetadataExtractor(func(s Session) any {
		// Return something that cannot be marshaled to JSON
		return make(chan int)
	}))
	handler(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, res.Code)
	}

	if !strings.Contains(res.Body.String(), "problem serializing session data") {
		t.Error("Response should contain serialization error message")
	}
}

// Test SessionResponse struct

func TestSessionResponse_JSONMarshaling(t *testing.T) {
	response := SessionResponse{
		UserID:   "test-user-id",
		TenantID: "test-tenant-id",
		Metadata: map[string]string{
			"role":  "admin",
			"email": "test@example.com",
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal SessionResponse: %v", err)
	}

	var unmarshaled SessionResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal SessionResponse: %v", err)
	}

	if unmarshaled.UserID != response.UserID {
		t.Errorf("Expected UserID %s, got %s", response.UserID, unmarshaled.UserID)
	}
	if unmarshaled.TenantID != response.TenantID {
		t.Errorf("Expected TenantID %s, got %s", response.TenantID, unmarshaled.TenantID)
	}

	// Verify metadata structure
	metadata, ok := unmarshaled.Metadata.(map[string]any)
	if !ok {
		t.Fatal("Metadata should be a map")
	}
	if metadata["role"] != "admin" {
		t.Errorf("Expected role 'admin', got %v", metadata["role"])
	}
}

// Test appOptionFunc

func TestAppOptionFunc(t *testing.T) {
	var appliedApp *WristbandApp
	option := appOptionFunc(func(app *WristbandApp) {
		appliedApp = app
	})

	app := &WristbandApp{}
	option.apply(app)

	if appliedApp != app {
		t.Error("Option function should receive the correct app instance")
	}
}

func TestWithCookieOptions(t *testing.T) {
	cookieOpts := CookieOptions{
		Domain:                          "example.com",
		Path:                            "/test",
		MaxAge:                          7200,
		DangerouslyDisableSecureCookies: true,
	}

	option := WithCookieOptions(cookieOpts)
	auth := &WristbandAuth{}
	option.apply(auth)

	if auth.cookieOptions.Domain != cookieOpts.Domain {
		t.Errorf("Expected Domain %s, got %s", cookieOpts.Domain, auth.cookieOptions.Domain)
	}
	if auth.cookieOptions.Path != cookieOpts.Path {
		t.Errorf("Expected Path %s, got %s", cookieOpts.Path, auth.cookieOptions.Path)
	}
	if auth.cookieOptions.MaxAge != cookieOpts.MaxAge {
		t.Errorf("Expected MaxAge %d, got %d", cookieOpts.MaxAge, auth.cookieOptions.MaxAge)
	}
	if auth.cookieOptions.DangerouslyDisableSecureCookies != cookieOpts.DangerouslyDisableSecureCookies {
		t.Errorf("Expected DangerouslyDisableSecureCookies %v, got %v",
			cookieOpts.DangerouslyDisableSecureCookies, auth.cookieOptions.DangerouslyDisableSecureCookies)
	}
}

// Benchmark tests

func BenchmarkSessionHandler(b *testing.B) {
	sessionManager := newMockSessionManager()
	session := &Session{
		UserInfo: UserInfoResponse{Sub: "test-user", TenantID: "test-tenant-id"},
	}
	sessionManager.sessions["test-session"] = session

	app := WristbandApp{
		SessionManager: sessionManager,
	}

	handler := app.SessionHandler()
	req := httptest.NewRequest("GET", "http://example.com/session", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := httptest.NewRecorder()
		handler(res, req)
	}
}

func BenchmarkSessionJSONMarshaling(b *testing.B) {
	session := &Session{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now(),
		ExpiresIn:    time.Hour,
		UserInfo: UserInfoResponse{
			Sub:      "test-user",
			Email:    "test@example.com",
			Name:     "Test User",
			TenantID: "test-tenant",
			IDPName:  "test-idp",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(session)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test login options

func TestWithDefaultTenantCustomDomain(t *testing.T) {
	opts := NewLoginOptions(WithDefaultTenantCustomDomain("custom.acme.com"))
	if opts.defaultTenantCustomDomain != "custom.acme.com" {
		t.Errorf("Expected %q, got %q", "custom.acme.com", opts.defaultTenantCustomDomain)
	}
}

func TestWithDefaultTenantName(t *testing.T) {
	opts := NewLoginOptions(WithDefaultTenantName("acme"))
	if opts.defaultTenantName != "acme" {
		t.Errorf("Expected %q, got %q", "acme", opts.defaultTenantName)
	}
}

func TestWithReturnURL(t *testing.T) {
	opts := NewLoginOptions(WithReturnURL("https://example.com/dashboard"))
	if opts.returnURL != "https://example.com/dashboard" {
		t.Errorf("Expected %q, got %q", "https://example.com/dashboard", opts.returnURL)
	}
}

func TestCallbackContext_Session(t *testing.T) {
	ctx := CallbackContext{
		TokenResponse: TokenResponse{
			AccessToken:  "access-tok",
			RefreshToken: "refresh-tok",
			IDToken:      "id-tok",
			ExpiresIn:    3600,
		},
		UserInfo: UserInfoResponse{
			Sub:      "user-123",
			Name:     "Alice",
			Email:    "alice@example.com",
			TenantID: "tenant-abc",
		},
		TenantName:         "acme",
		CustomTenantDomain: "custom.acme.com",
	}

	session := ctx.Session()

	if session.AccessToken != "access-tok" {
		t.Errorf("Expected AccessToken %q, got %q", "access-tok", session.AccessToken)
	}
	if session.RefreshToken != "refresh-tok" {
		t.Errorf("Expected RefreshToken %q, got %q", "refresh-tok", session.RefreshToken)
	}
	if session.IDToken != "id-tok" {
		t.Errorf("Expected IDToken %q, got %q", "id-tok", session.IDToken)
	}
	if session.ExpiresIn != time.Hour {
		t.Errorf("Expected ExpiresIn %v, got %v", time.Hour, session.ExpiresIn)
	}
	if session.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
	if session.UserInfo.Sub != "user-123" {
		t.Errorf("Expected UserInfo.Sub %q, got %q", "user-123", session.UserInfo.Sub)
	}
	if session.TenantName != "acme" {
		t.Errorf("Expected TenantName %q, got %q", "acme", session.TenantName)
	}
	if session.CustomTenantDomain != "custom.acme.com" {
		t.Errorf("Expected CustomTenantDomain %q, got %q", "custom.acme.com", session.CustomTenantDomain)
	}
}

// Test clearAllLoginCookies

func TestWristbandApp_ClearAllLoginCookies(t *testing.T) {
	app := WristbandApp{}
	mockCtx := newMockHTTPContext()
	mockCookieReq := mockCtx.cookieRequest.(*mockCookieRequest)

	// Add login cookies and a regular cookie
	mockCookieReq.cookies["login#state1#1000"] = "val1"
	mockCookieReq.cookies["login#state2#2000"] = "val2"
	mockCookieReq.cookies["session-id"] = "sess-val"

	app.clearAllLoginCookies(mockCtx)

	if len(mockCtx.clearedCookies) != 2 {
		t.Errorf("Expected 2 cookies cleared, got %d", len(mockCtx.clearedCookies))
	}

	clearedSet := make(map[string]bool)
	for _, name := range mockCtx.clearedCookies {
		clearedSet[name] = true
	}
	if !clearedSet["login#state1#1000"] || !clearedSet["login#state2#2000"] {
		t.Error("Both login cookies should be cleared")
	}
	if clearedSet["session-id"] {
		t.Error("Non-login cookie should not be cleared")
	}
}

func TestWristbandApp_ClearAllLoginCookies_NoCookies(t *testing.T) {
	app := WristbandApp{}
	mockCtx := newMockHTTPContext()

	// No cookies at all
	app.clearAllLoginCookies(mockCtx)

	if len(mockCtx.clearedCookies) != 0 {
		t.Errorf("Expected 0 cookies cleared, got %d", len(mockCtx.clearedCookies))
	}
}

// Test cookie cleanup functionality
func TestWristbandAuth_CleanupOldLoginCookies(t *testing.T) {
	auth := WristbandAuth{
		cookieEncryption: newMockCookieEncryption(),
	}

	mockCtx := newMockHTTPContext()
	mockCookieReq := mockCtx.cookieRequest.(*mockCookieRequest)

	// Add 5 login cookies with different timestamps
	// Using the actual LoginStateCookiePrefix which is "login#"
	now := time.Now().UnixMilli()
	cookieNames := []string{
		fmt.Sprintf("login#state1#%d", now-4000), // oldest
		fmt.Sprintf("login#state2#%d", now-3000),
		fmt.Sprintf("login#state3#%d", now-2000),
		fmt.Sprintf("login#state4#%d", now-1000),
		fmt.Sprintf("login#state5#%d", now), // newest
	}

	for _, name := range cookieNames {
		mockCookieReq.cookies[name] = "dummy-value"
	}

	// Add a non-login cookie to verify it's not cleared
	mockCookieReq.cookies["other-cookie"] = "other-value"

	// Call cleanup
	auth.cleanupOldLoginCookies(mockCtx)

	// Should keep only the 2 most recent cookies (state4 and state5)
	// and clear the 3 oldest (state1, state2, state3)
	if len(mockCtx.clearedCookies) != 3 {
		t.Errorf("Expected 3 cookies to be cleared, got %d", len(mockCtx.clearedCookies))
	}

	// Verify the correct cookies were cleared (the 3 oldest)
	clearedSet := make(map[string]bool)
	for _, name := range mockCtx.clearedCookies {
		clearedSet[name] = true
	}

	if !clearedSet[cookieNames[0]] || !clearedSet[cookieNames[1]] || !clearedSet[cookieNames[2]] {
		t.Error("The 3 oldest cookies should have been cleared")
	}

	if clearedSet[cookieNames[3]] || clearedSet[cookieNames[4]] {
		t.Error("The 2 newest cookies should not have been cleared")
	}

	if clearedSet["other-cookie"] {
		t.Error("Non-login cookies should not be cleared")
	}
}

// Test cookie name format with timestamp
func TestLoginStateCookieName_WithTimestamp(t *testing.T) {
	stateStr := "test-state-123"
	timestamp := int64(1634567890123)

	cookieName := loginStateCookieName(stateStr, timestamp)

	// LoginStateCookiePrefix is "login#"
	expectedName := "login#test-state-123#1634567890123"
	if cookieName != expectedName {
		t.Errorf("Expected cookie name %s, got %s", expectedName, cookieName)
	}

	// Test parsing
	parsedState, parsedTimestamp, err := parseLoginStateCookieName(cookieName)
	if err != nil {
		t.Fatalf("Failed to parse cookie name: %v", err)
	}

	if parsedState != stateStr {
		t.Errorf("Expected parsed state %s, got %s", stateStr, parsedState)
	}

	if parsedTimestamp != timestamp {
		t.Errorf("Expected parsed timestamp %d, got %d", timestamp, parsedTimestamp)
	}
}

// Test LoginState with CreatedAt field
func TestLoginState_CreatedAt(t *testing.T) {
	queryValues := url.Values{}
	queryValues.Set("return_url", "http://example.com/return")

	options := NewLoginOptions(WithCustomState(map[string]any{"key": "value"}))

	state := CreateLoginState(queryValues, options)

	if state.CreatedAt == 0 {
		t.Error("CreatedAt should be set to current timestamp")
	}

	// Verify the cookie name includes the timestamp
	// LoginStateCookiePrefix is "login#"
	cookieName := state.CookieName()
	if !strings.Contains(cookieName, "login#") {
		t.Error("Cookie name should start with the login state prefix")
	}

	// Parse and verify
	_, parsedTimestamp, err := parseLoginStateCookieName(cookieName)
	if err != nil {
		t.Fatalf("Failed to parse cookie name: %v", err)
	}

	if parsedTimestamp != state.CreatedAt {
		t.Errorf("Expected timestamp %d in cookie name, got %d", state.CreatedAt, parsedTimestamp)
	}
}
