package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- resolveReturnURL ---

func TestResolveReturnURL_FromQueryParam(t *testing.T) {
	ctx := newMockHTTPContext()
	ctx.queryValues.Set("return_url", "https://example.com/dashboard")

	got := (*LoginOptions)(nil).resolveReturnURL(ctx)
	if got != "https://example.com/dashboard" {
		t.Errorf("Expected URL from query, got %q", got)
	}
}

func TestResolveReturnURL_FromOptions(t *testing.T) {
	ctx := newMockHTTPContext()
	opts := NewLoginOptions(WithReturnURL("https://example.com/settings"))

	got := opts.resolveReturnURL(ctx)
	if got != "https://example.com/settings" {
		t.Errorf("Expected URL from options, got %q", got)
	}
}

func TestResolveReturnURL_QueryOverridesOptions(t *testing.T) {
	ctx := newMockHTTPContext()
	ctx.queryValues.Set("return_url", "https://example.com/from-query")
	opts := NewLoginOptions(WithReturnURL("https://example.com/from-options"))

	got := opts.resolveReturnURL(ctx)
	if got != "https://example.com/from-query" {
		t.Errorf("Expected query URL to take precedence, got %q", got)
	}
}

func TestResolveReturnURL_TooLong(t *testing.T) {
	ctx := newMockHTTPContext()
	longURL := "https://example.com/" + strings.Repeat("a", ReturnURLMaxLength)
	ctx.queryValues.Set("return_url", longURL)

	got := (*LoginOptions)(nil).resolveReturnURL(ctx)
	if got != "" {
		t.Errorf("Expected empty string for URL exceeding max length, got %q", got)
	}
}

func TestResolveReturnURL_Empty(t *testing.T) {
	ctx := newMockHTTPContext()
	got := (*LoginOptions)(nil).resolveReturnURL(ctx)
	if got != "" {
		t.Errorf("Expected empty string, got %q", got)
	}
}

// --- loginBaseURL ---

func TestLoginBaseURL_FromTenantCustomDomain(t *testing.T) {
	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "custom.acme.com")

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

	got, err := auth.loginBaseURL(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "custom.acme.com" {
		t.Errorf("Expected %q, got %q", "custom.acme.com", got)
	}
}

func TestLoginBaseURL_FromTenantNameQuery(t *testing.T) {
	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")

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

	got, err := auth.loginBaseURL(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "acme-app.wristband.dev" {
		t.Errorf("Expected %q, got %q", "acme-app.wristband.dev", got)
	}
}

func TestLoginBaseURL_NilOptions(t *testing.T) {
	ctx := newMockHTTPContext()
	// No tenant_name, no tenant_custom_domain

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

	_, err := auth.loginBaseURL(ctx, nil)
	if !errors.Is(err, ErrTenantNameNotFound) {
		t.Errorf("Expected ErrTenantNameNotFound, got %v", err)
	}
}

func TestLoginBaseURL_DefaultTenantCustomDomain(t *testing.T) {
	ctx := newMockHTTPContext()

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

	opts := NewLoginOptions(WithDefaultTenantCustomDomain("default-custom.acme.com"))
	got, err := auth.loginBaseURL(ctx, opts)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "default-custom.acme.com" {
		t.Errorf("Expected %q, got %q", "default-custom.acme.com", got)
	}
}

func TestLoginBaseURL_DefaultTenantName(t *testing.T) {
	ctx := newMockHTTPContext()

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

	opts := NewLoginOptions(WithDefaultTenantName("fallback-tenant"))
	got, err := auth.loginBaseURL(ctx, opts)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "fallback-tenant-app.wristband.dev" {
		t.Errorf("Expected %q, got %q", "fallback-tenant-app.wristband.dev", got)
	}
}

func TestLoginBaseURL_EmptyOptions_ReturnsError(t *testing.T) {
	ctx := newMockHTTPContext()

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

	opts := NewLoginOptions() // empty, no defaults
	_, err := auth.loginBaseURL(ctx, opts)
	if !errors.Is(err, ErrTenantNameNotFound) {
		t.Errorf("Expected ErrTenantNameNotFound, got %v", err)
	}
}

// --- CreateLoginState ---

func TestCreateLoginState_NilOptions(t *testing.T) {
	queryValues := url.Values{}
	queryValues.Set("return_url", "https://example.com/return")

	state := CreateLoginState(queryValues, nil)

	if state.ReturnURL != "https://example.com/return" {
		t.Errorf("Expected return URL from query, got %q", state.ReturnURL)
	}
	if state.Nonce == "" {
		t.Error("Expected Nonce to be generated")
	}
	if state.CodeVerifier == "" {
		t.Error("Expected CodeVerifier to be generated")
	}
	if state.CustomState != nil {
		t.Error("Expected nil CustomState")
	}
}

func TestCreateLoginState_OptionsOverridesQuery(t *testing.T) {
	queryValues := url.Values{}
	queryValues.Set("return_url", "https://query.example.com")

	opts := NewLoginOptions(
		WithReturnURL("https://options.example.com"),
		WithCustomState(map[string]any{"key": "value"}),
	)
	state := CreateLoginState(queryValues, opts)

	if state.ReturnURL != "https://options.example.com" {
		t.Errorf("Expected options return URL, got %q", state.ReturnURL)
	}
	m, ok := state.CustomState.(map[string]any)
	if !ok || m["key"] != "value" {
		t.Error("Expected custom state from options")
	}
}

// --- HandleLogin ---

func TestHandleLogin_TenantNameNotFound_VanityDomain(t *testing.T) {
	// No tenant_name in query, no defaults, should redirect to vanity domain login page
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("return_url", "https://example.com/dashboard")

	redirectURL, err := auth.HandleLogin(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(redirectURL, "app.wristband.dev/login") {
		t.Errorf("Expected vanity domain redirect, got %q", redirectURL)
	}
	if !strings.Contains(redirectURL, "client_id=test-client") {
		t.Errorf("Expected client_id in URL, got %q", redirectURL)
	}
	// return_url should be encoded in state param
	if !strings.Contains(redirectURL, "state=") {
		t.Errorf("Expected state param with return_url, got %q", redirectURL)
	}
}

func TestHandleLogin_TenantNameNotFound_CustomLoginPage(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:                      "https://app.wristband.dev/login",
			RedirectURI:                   "https://app.example.com/callback",
			CustomApplicationLoginPageURL: "https://custom.example.com/login",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	redirectURL, err := auth.HandleLogin(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(redirectURL, "custom.example.com/login") {
		t.Errorf("Expected custom login page URL, got %q", redirectURL)
	}
}

func TestHandleLogin_WithTenant_Success(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")

	redirectURL, err := auth.HandleLogin(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should produce an authorize URL for the tenant
	if !strings.Contains(redirectURL, "acme-app.wristband.dev") {
		t.Errorf("Expected tenant authorize URL, got %q", redirectURL)
	}
	if !strings.Contains(redirectURL, "client_id=test-client") {
		t.Errorf("Expected client_id in URL, got %q", redirectURL)
	}
	if !strings.Contains(redirectURL, "response_type=code") {
		t.Errorf("Expected response_type=code in URL, got %q", redirectURL)
	}

	// Should have written a login state cookie
	if len(ctx.writtenCookies) == 0 {
		t.Error("Expected at least one login state cookie to be written")
	}

	// Verify a cookie with login# prefix was written
	foundLoginCookie := false
	for name := range ctx.writtenCookies {
		if strings.HasPrefix(name, LoginStateCookiePrefix) {
			foundLoginCookie = true
			break
		}
	}
	if !foundLoginCookie {
		t.Error("Expected a login state cookie to be written")
	}
}

func TestHandleLogin_WithDefaultTenantName(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	opts := NewLoginOptions(WithDefaultTenantName("default-tenant"))

	redirectURL, err := auth.HandleLogin(ctx, opts)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(redirectURL, "default-tenant-app.wristband.dev") {
		t.Errorf("Expected default tenant in URL, got %q", redirectURL)
	}
}

func TestHandleLogin_WriteCookieError(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")
	ctx.writeCookieError = fmt.Errorf("cookie write failed")

	_, err := auth.HandleLogin(ctx, nil)
	if err == nil {
		t.Fatal("Expected error when WriteCookie fails")
	}
	if !strings.Contains(err.Error(), "failed to write login state cookie") {
		t.Errorf("Expected cookie write error, got %v", err)
	}
}

func TestHandleLogin_EncryptCookieError(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()
	// Override cookie encryption to return error
	mockEnc := newMockCookieEncryption()
	mockEnc.encryptErr = fmt.Errorf("encryption failed")
	auth.cookieEncryption = mockEnc

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")

	_, err := auth.HandleLogin(ctx, nil)
	if err == nil {
		t.Fatal("Expected error when cookie encryption fails")
	}
	if !strings.Contains(err.Error(), "failed to encrypt cookie") {
		t.Errorf("Expected encryption error, got %v", err)
	}
}

func TestHandleLogin_WithAdditionalScopes(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")

	opts := &LoginOptions{
		authorizeRequestOpts: []AuthorizeRequestOption{
			WithAdditionalScopes("profile", "email"),
		},
	}

	redirectURL, err := auth.HandleLogin(ctx, opts)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(redirectURL, "scope=") {
		t.Errorf("Expected scope in URL, got %q", redirectURL)
	}
}

// --- GetLoginStateCookie ---

func TestGetLoginStateCookie_MissingState(t *testing.T) {
	ctx := newMockHTTPContext()
	enc := newMockCookieEncryption()

	_, err := GetLoginStateCookie(enc, ctx)
	if err == nil {
		t.Fatal("Expected error for missing state param")
	}
}

func TestGetLoginStateCookie_NoMatchingCookie(t *testing.T) {
	ctx := newMockHTTPContext()
	ctx.queryValues.Set("state", "unknown-key")
	enc := newMockCookieEncryption()

	_, err := GetLoginStateCookie(enc, ctx)
	if !errors.Is(err, ErrorNoLoginState) {
		t.Errorf("Expected ErrorNoLoginState, got %v", err)
	}
}

func TestGetLoginStateCookie_Success(t *testing.T) {
	loginState := LoginState{
		ReturnURL:      "https://example.com/return",
		Nonce:          "test-nonce",
		CodeVerifier:   "test-verifier",
		StateCookieKey: "my-state-key",
		CreatedAt:      1700000000000,
	}
	stateJSON, _ := json.Marshal(loginState)

	// The cookie name uses the full format: login#<state_key>#<timestamp>
	cookieName := loginStateCookieName("my-state-key", 1700000000000)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("state", "my-state-key")
	mockCookieReq := ctx.cookieRequest.(*mockCookieRequest)
	mockCookieReq.cookies[cookieName] = "encrypted-state-value"

	enc := newMockCookieEncryption()
	enc.encryptedValues[cookieName] = string(stateJSON)

	got, err := GetLoginStateCookie(enc, ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got.ReturnURL != "https://example.com/return" {
		t.Errorf("Expected ReturnURL %q, got %q", "https://example.com/return", got.ReturnURL)
	}
	if got.Nonce != "test-nonce" {
		t.Errorf("Expected Nonce %q, got %q", "test-nonce", got.Nonce)
	}
	if got.CodeVerifier != "test-verifier" {
		t.Errorf("Expected CodeVerifier %q, got %q", "test-verifier", got.CodeVerifier)
	}
}

func TestGetLoginStateCookie_ReadEncryptedError(t *testing.T) {
	cookieName := loginStateCookieName("my-state-key", 1700000000000)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("state", "my-state-key")
	mockCookieReq := ctx.cookieRequest.(*mockCookieRequest)
	mockCookieReq.cookies[cookieName] = "encrypted"

	enc := newMockCookieEncryption()
	enc.readErr = fmt.Errorf("decryption failed")

	_, err := GetLoginStateCookie(enc, ctx)
	if err == nil {
		t.Fatal("Expected error from ReadEncrypted")
	}
}

func TestGetLoginStateCookie_InvalidJSON(t *testing.T) {
	cookieName := loginStateCookieName("my-state-key", 1700000000000)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("state", "my-state-key")
	mockCookieReq := ctx.cookieRequest.(*mockCookieRequest)
	mockCookieReq.cookies[cookieName] = "encrypted"

	enc := newMockCookieEncryption()
	enc.encryptedValues[cookieName] = "not-json"

	_, err := GetLoginStateCookie(enc, ctx)
	if err == nil {
		t.Fatal("Expected JSON unmarshal error")
	}
}

func TestGetLoginStateCookie_SkipsNonLoginCookies(t *testing.T) {
	ctx := newMockHTTPContext()
	ctx.queryValues.Set("state", "my-state-key")
	mockCookieReq := ctx.cookieRequest.(*mockCookieRequest)
	// Add a non-login cookie that won't match
	mockCookieReq.cookies["session-id"] = "some-value"
	// Add an unparseable login cookie
	mockCookieReq.cookies["login#bad-format"] = "some-value"

	enc := newMockCookieEncryption()

	_, err := GetLoginStateCookie(enc, ctx)
	if !errors.Is(err, ErrorNoLoginState) {
		t.Errorf("Expected ErrorNoLoginState, got %v", err)
	}
}

// --- HandleCallback ---

func TestHandleCallback_MissingTenantName(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code-123")
	// No tenant_name

	_, err := auth.HandleCallback(ctx)
	if err == nil {
		t.Fatal("Expected error when tenant name is missing")
	}
}

func TestHandleCallback_MissingCode(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")
	// No code

	_, err := auth.HandleCallback(ctx)
	if err == nil {
		t.Fatal("Expected error when code is missing")
	}
	var ipErr InvalidParameterError
	if !errors.As(err, &ipErr) {
		t.Errorf("Expected InvalidParameterError, got %T", err)
	}
}

func TestHandleCallback_RequestError(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("error", "access_denied")
	ctx.queryValues.Set("error_description", "user denied")

	_, err := auth.HandleCallback(ctx)
	if err == nil {
		t.Fatal("Expected error for request error params")
	}
	var wristbandErr *WristbandError
	if !errors.As(err, &wristbandErr) {
		t.Errorf("Expected WristbandError, got %T", err)
	}
}

func TestHandleCallback_NoLoginState(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, _ := authConfig.WristbandAuth()

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code-123")
	ctx.queryValues.Set("tenant_name", "acme")
	ctx.queryValues.Set("state", "nonexistent-state")

	_, err := auth.HandleCallback(ctx)
	if err == nil {
		t.Fatal("Expected error when login state cookie is not found")
	}
	// Should be a RedirectError since the login state failed to retrieve
	if _, ok := IsRedirectError(err); !ok {
		t.Errorf("Expected RedirectError, got %T: %v", err, err)
	}
}

func TestHandleCallback_TokenExchangeFailure(t *testing.T) {
	// Token endpoint that returns 400
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	loginState := LoginState{
		ReturnURL:      "https://example.com/return",
		Nonce:          "test-nonce",
		CodeVerifier:   "test-verifier",
		StateCookieKey: "my-state-key",
		CreatedAt:      1700000000000,
	}
	stateJSON, _ := json.Marshal(loginState)
	cookieName := loginStateCookieName("my-state-key", 1700000000000)

	enc := newMockCookieEncryption()
	enc.encryptedValues[cookieName] = string(stateJSON)

	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
		httpClient: tokenServer.Client(),
	}
	auth, _ := authConfig.WristbandAuth()
	auth.tokenURL = tokenServer.URL
	auth.cookieEncryption = enc

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code-123")
	ctx.queryValues.Set("tenant_name", "acme")
	ctx.queryValues.Set("state", "my-state-key")
	mockCookieReq := ctx.cookieRequest.(*mockCookieRequest)
	mockCookieReq.cookies[cookieName] = "encrypted"

	_, err := auth.HandleCallback(ctx)
	if err == nil {
		t.Fatal("Expected error from token exchange")
	}
	if !strings.Contains(err.Error(), "failed to exchange code for tokens") {
		t.Errorf("Expected token exchange error, got %v", err)
	}
}

func TestHandleCallback_Success(t *testing.T) {
	loginState := LoginState{
		ReturnURL:      "https://example.com/return",
		Nonce:          "test-nonce",
		CodeVerifier:   "test-verifier",
		StateCookieKey: "my-state-key",
		CreatedAt:      1700000000000,
	}
	stateJSON, _ := json.Marshal(loginState)
	cookieName := loginStateCookieName("my-state-key", 1700000000000)

	// Mock token + userinfo endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := TokenResponse{
			AccessToken:  "access-tok",
			RefreshToken: "refresh-tok",
			IDToken:      "id-tok",
			ExpiresIn:    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		userInfo := UserInfoResponse{
			Sub:      "user-123",
			Name:     "Alice",
			Email:    "alice@example.com",
			TenantId: "tenant-abc",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")

	enc := newMockCookieEncryption()
	enc.encryptedValues[cookieName] = string(stateJSON)

	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
		httpClient: server.Client(),
	}
	auth, _ := authConfig.WristbandAuth()
	auth.tokenURL = server.URL + "/token"
	auth.endpointRoot = serverHost
	auth.cookieEncryption = enc

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code-123")
	ctx.queryValues.Set("tenant_name", "acme")
	ctx.queryValues.Set("state", "my-state-key")
	mockCookieReq := ctx.cookieRequest.(*mockCookieRequest)
	mockCookieReq.cookies[cookieName] = "encrypted"

	callbackCtx, err := auth.HandleCallback(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if callbackCtx.TokenResponse.AccessToken != "access-tok" {
		t.Errorf("Expected AccessToken %q, got %q", "access-tok", callbackCtx.TokenResponse.AccessToken)
	}
	if callbackCtx.UserInfo.Sub != "user-123" {
		t.Errorf("Expected Sub %q, got %q", "user-123", callbackCtx.UserInfo.Sub)
	}
	if callbackCtx.TenantName != "acme" {
		t.Errorf("Expected TenantName %q, got %q", "acme", callbackCtx.TenantName)
	}
}

// --- parseLoginStateCookieName ---

func TestParseLoginStateCookieName_MissingPrefix(t *testing.T) {
	_, _, err := parseLoginStateCookieName("invalid-name")
	if err == nil {
		t.Fatal("Expected error for missing prefix")
	}
}

func TestParseLoginStateCookieName_BadFormat(t *testing.T) {
	_, _, err := parseLoginStateCookieName("login#only-one-part")
	if err == nil {
		t.Fatal("Expected error for bad format")
	}
}

func TestParseLoginStateCookieName_BadTimestamp(t *testing.T) {
	_, _, err := parseLoginStateCookieName("login#state-key#not-a-number")
	if err == nil {
		t.Fatal("Expected error for invalid timestamp")
	}
}
