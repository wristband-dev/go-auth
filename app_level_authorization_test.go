package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	appLevelVanityDomain = "auth.example.com"
	appLevelRootDomain   = "business.invotastic.com"
)

func newAppLevelAuth(t *testing.T, useTenantSubdomains bool, appLevelEnabled *bool, customLoginPageURL string) WristbandAuth {
	t.Helper()
	host := appLevelRootDomain
	if useTenantSubdomains {
		host = TenantNameToken + "." + appLevelRootDomain
	}
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: appLevelVanityDomain,
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:                                "https://" + host + "/api/auth/login",
			RedirectURI:                             "https://" + host + "/api/auth/callback",
			CustomApplicationLoginPageURL:           customLoginPageURL,
			ApplicationAuthorizationRequestsEnabled: appLevelEnabled,
		},
	}
	auth, err := authConfig.WristbandAuth(WithCookieOptions(CookieOptions{Path: "/", MaxAge: 3600, SameSite: http.SameSiteLaxMode}))
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}
	return auth
}

func loginStateSetCookies(t *testing.T, rec *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	var loginCookies []*http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, LoginStateCookiePrefix) {
			loginCookies = append(loginCookies, cookie)
		}
	}
	return loginCookies
}

func TestHandleLogin_AppLevel_UnresolvedTenantRedirectsToAppLevelAuthorizeEndpoint(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "")
	req := httptest.NewRequest(http.MethodGet, "https://"+appLevelRootDomain+"/api/auth/login?return_url=/settings&login_hint=a@b.com", nil)
	rec := httptest.NewRecorder()

	authorizeURL, err := auth.HandleLogin(auth.NewStandardHttpContext(rec, req), NewLoginOptions())
	if err != nil {
		t.Fatalf("HandleLogin returned error: %v", err)
	}

	parsed, _ := url.Parse(authorizeURL)
	if parsed.Host != appLevelVanityDomain || parsed.Path != "/api/v1/oauth2/authorize" {
		t.Errorf("Expected the app-level Authorize Endpoint, got %q", authorizeURL)
	}
	if parsed.Query().Get("login_hint") != "a@b.com" {
		t.Errorf("Expected login_hint to be passed through, got %q", parsed.Query().Get("login_hint"))
	}

	cookies := loginStateSetCookies(t, rec)
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 login state cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != appLevelRootDomain {
		t.Errorf("Expected the login state cookie on the root domain, got domain %q", cookies[0].Domain)
	}
	if !strings.HasPrefix(cookies[0].Name, LoginStateCookiePrefix+parsed.Query().Get("state")+"#") {
		t.Errorf("Expected the login state cookie to match the state param, got %q", cookies[0].Name)
	}
}

func TestHandleLogin_AppLevel_HostOnlyCookieWithoutTenantSubdomains(t *testing.T) {
	auth := newAppLevelAuth(t, false, nil, "")
	req := httptest.NewRequest(http.MethodGet, "https://"+appLevelRootDomain+"/api/auth/login", nil)
	rec := httptest.NewRecorder()

	authorizeURL, err := auth.HandleLogin(auth.NewStandardHttpContext(rec, req), NewLoginOptions())
	if err != nil {
		t.Fatalf("HandleLogin returned error: %v", err)
	}
	if !strings.HasPrefix(authorizeURL, "https://"+appLevelVanityDomain+"/api/v1/oauth2/authorize?") {
		t.Errorf("Expected the app-level Authorize Endpoint, got %q", authorizeURL)
	}
	cookies := loginStateSetCookies(t, rec)
	if len(cookies) != 1 || cookies[0].Domain != "" {
		t.Errorf("Expected 1 host-only login state cookie, got %v", cookies)
	}
}

func TestHandleLogin_AppLevel_CustomLoginPageHasNoEffectWhenEnabled(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "https://custom.example.com/login")
	req := httptest.NewRequest(http.MethodGet, "https://"+appLevelRootDomain+"/api/auth/login", nil)

	authorizeURL, err := auth.HandleLogin(auth.NewStandardHttpContext(httptest.NewRecorder(), req), NewLoginOptions())
	if err != nil {
		t.Fatalf("HandleLogin returned error: %v", err)
	}
	if !strings.HasPrefix(authorizeURL, "https://"+appLevelVanityDomain+"/api/v1/oauth2/authorize?") {
		t.Errorf("Expected the app-level Authorize Endpoint, got %q", authorizeURL)
	}
}

func TestHandleLogin_AppLevel_ResolvedTenantUsesRootDomainCookie(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "")
	req := httptest.NewRequest(http.MethodGet, "https://devs4you."+appLevelRootDomain+"/api/auth/login", nil)
	rec := httptest.NewRecorder()

	authorizeURL, err := auth.HandleLogin(auth.NewStandardHttpContext(rec, req), NewLoginOptions())
	if err != nil {
		t.Fatalf("HandleLogin returned error: %v", err)
	}
	if !strings.HasPrefix(authorizeURL, "https://devs4you-"+appLevelVanityDomain+"/api/v1/oauth2/authorize?") {
		t.Errorf("Expected the tenant-level Authorize Endpoint, got %q", authorizeURL)
	}
	cookies := loginStateSetCookies(t, rec)
	if len(cookies) != 1 || cookies[0].Domain != appLevelRootDomain {
		t.Errorf("Expected 1 login state cookie on the root domain, got %v", cookies)
	}
}

func TestHandleLogin_AppLevelDisabled_HostOnlyCookieAndLoginPage(t *testing.T) {
	auth := newAppLevelAuth(t, true, boolPtr(false), "")

	tenantReq := httptest.NewRequest(http.MethodGet, "https://devs4you."+appLevelRootDomain+"/api/auth/login", nil)
	tenantRec := httptest.NewRecorder()
	if _, err := auth.HandleLogin(auth.NewStandardHttpContext(tenantRec, tenantReq), NewLoginOptions()); err != nil {
		t.Fatalf("HandleLogin returned error: %v", err)
	}
	if cookies := loginStateSetCookies(t, tenantRec); len(cookies) != 1 || cookies[0].Domain != "" {
		t.Errorf("Expected 1 host-only login state cookie, got %v", cookies)
	}

	rootReq := httptest.NewRequest(http.MethodGet, "https://"+appLevelRootDomain+"/api/auth/login?return_url=/a?b=c", nil)
	rootRec := httptest.NewRecorder()
	loginPageURL, err := auth.HandleLogin(auth.NewStandardHttpContext(rootRec, rootReq), NewLoginOptions(WithReturnURL("/dashboard")))
	if err != nil {
		t.Fatalf("HandleLogin returned error: %v", err)
	}
	expected := "https://" + appLevelVanityDomain + "/login?client_id=test-client&state=%2Fdashboard"
	if loginPageURL != expected {
		t.Errorf("Expected %q, got %q", expected, loginPageURL)
	}
	if cookies := loginStateSetCookies(t, rootRec); len(cookies) != 0 {
		t.Errorf("Expected no login state cookie for the login page, got %v", cookies)
	}
}

func TestRequestTenantName_BareRootDomainIsUnresolved(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "")
	req := newMockHTTPRequest()
	req.host = appLevelRootDomain

	tenantName, err := auth.RequestTenantName(req)
	if err != nil || tenantName != "" {
		t.Errorf("Expected no tenant name for the bare root domain, got %q (err: %v)", tenantName, err)
	}
}

func newAppLevelCallbackContext(auth *WristbandAuth, returnURL string, createdAt time.Time) *mockHTTPContext {
	loginState := LoginState{
		ReturnURL:      returnURL,
		Nonce:          "test-nonce",
		CodeVerifier:   "test-verifier",
		StateCookieKey: "my-state-key",
		CreatedAt:      createdAt.UnixMilli(),
	}
	stateJSON, _ := json.Marshal(loginState)
	cookieName := loginStateCookieName("my-state-key", loginState.CreatedAt)

	enc := newMockCookieEncryption()
	enc.encryptedValues[cookieName] = string(stateJSON)
	auth.cookieEncryption = enc

	ctx := newMockHTTPContext()
	ctx.host = "devs4you." + appLevelRootDomain
	ctx.queryValues.Set("code", "auth-code")
	ctx.queryValues.Set("state", "my-state-key")
	ctx.cookieRequest.(*mockCookieRequest).cookies[cookieName] = "encrypted"
	return ctx
}

func withMockTokenServer(t *testing.T, auth *WristbandAuth) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access-tok", ExpiresIn: 3600})
	})
	mux.HandleFunc("/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(UserInfoResponse{Sub: "user-123"})
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	auth.httpClient = server.Client()
	auth.tokenURL = server.URL + "/token"
	auth.endpointRoot = strings.TrimPrefix(server.URL, "https://")
}

func TestHandleCallback_ReturnURLValidation(t *testing.T) {
	tests := []struct {
		name      string
		appLevel  *bool
		returnURL string
		expected  string
	}{
		{"relative path", nil, "/settings?tab=billing", "/settings?tab=billing"},
		{"request host", nil, "https://devs4you." + appLevelRootDomain + "/dashboard", "https://devs4you." + appLevelRootDomain + "/dashboard"},
		{"root domain rewritten", nil, "https://" + appLevelRootDomain + "/dashboard?tab=1", "https://devs4you." + appLevelRootDomain + "/dashboard?tab=1"},
		{"root domain kept when disabled", boolPtr(false), "https://" + appLevelRootDomain + "/dashboard", "https://" + appLevelRootDomain + "/dashboard"},
		{"off-site", nil, "https://evil.com/phish", ""},
		{"protocol-relative", nil, "//evil.com/phish", ""},
		{"other tenant", nil, "https://other." + appLevelRootDomain + "/dashboard", ""},
		{"scheme downgrade", nil, "http://devs4you." + appLevelRootDomain + "/dashboard", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := newAppLevelAuth(t, true, tt.appLevel, "")
			withMockTokenServer(t, &auth)
			ctx := newAppLevelCallbackContext(&auth, tt.returnURL, time.Now())

			callbackCtx, err := auth.HandleCallback(ctx)
			if err != nil {
				t.Fatalf("HandleCallback returned error: %v", err)
			}
			if callbackCtx.LoginState.ReturnURL != tt.expected {
				t.Errorf("Expected return URL %q, got %q", tt.expected, callbackCtx.LoginState.ReturnURL)
			}
			if callbackCtx.TenantName != "devs4you" {
				t.Errorf("Expected tenant name %q, got %q", "devs4you", callbackCtx.TenantName)
			}
		})
	}
}

func TestHandleCallback_ExpiredLoginStateRedirectsToTenantLoginURL(t *testing.T) {
	for name, createdAt := range map[string]time.Time{
		"expired":   time.Now().Add(-(loginStateMaxAge + loginStateClockSkew + time.Second)),
		"in future": time.Now().Add(loginStateClockSkew + time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			auth := newAppLevelAuth(t, true, nil, "")
			ctx := newAppLevelCallbackContext(&auth, "", createdAt)

			_, err := auth.HandleCallback(ctx)
			redirectErr, ok := IsRedirectError(err)
			if !ok {
				t.Fatalf("Expected a redirect error, got %v", err)
			}
			expected := "https://devs4you." + appLevelRootDomain + "/api/auth/login"
			if redirectErr.URL != expected {
				t.Errorf("Expected redirect to %q, got %q", expected, redirectErr.URL)
			}
		})
	}
}

func TestHandleCallback_LoginStateWithinClockSkewIsAccepted(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "")
	withMockTokenServer(t, &auth)
	ctx := newAppLevelCallbackContext(&auth, "", time.Now().Add(-(loginStateMaxAge + loginStateClockSkew - time.Second)))

	if _, err := auth.HandleCallback(ctx); err != nil {
		t.Fatalf("HandleCallback returned error: %v", err)
	}
}

func TestHandleCallback_UndecryptableLoginStateRedirectsToTenantLoginURL(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "")
	ctx := newMockHTTPContext()
	ctx.host = "devs4you." + appLevelRootDomain
	ctx.queryValues.Set("code", "auth-code")
	ctx.queryValues.Set("state", "my-state-key")
	ctx.cookieRequest.(*mockCookieRequest).cookies[loginStateCookieName("my-state-key", time.Now().UnixMilli())] = "not-encrypted"

	_, err := auth.HandleCallback(ctx)
	redirectErr, ok := IsRedirectError(err)
	if !ok {
		t.Fatalf("Expected a redirect error, got %v", err)
	}
	if redirectErr.URL != "https://devs4you."+appLevelRootDomain+"/api/auth/login" {
		t.Errorf("Unexpected redirect URL %q", redirectErr.URL)
	}
}

func TestHandleCallback_MissingTenantSubdomain(t *testing.T) {
	auth := newAppLevelAuth(t, true, nil, "")
	ctx := newMockHTTPContext()
	ctx.host = appLevelRootDomain
	ctx.queryValues.Set("code", "auth-code")
	ctx.queryValues.Set("state", "my-state-key")

	_, err := auth.HandleCallback(ctx)
	var wristbandErr WristbandError
	if !errors.As(err, &wristbandErr) || wristbandErr.Code != "missing_tenant_subdomain" {
		t.Errorf("Expected a missing_tenant_subdomain error, got %v", err)
	}
}

func TestWristbandApp_ClearAllLoginCookies_OnRootDomain(t *testing.T) {
	app := WristbandApp{WristbandAuth: newAppLevelAuth(t, true, nil, "")}
	req := httptest.NewRequest(http.MethodGet, "https://devs4you."+appLevelRootDomain+"/api/auth/callback", nil)
	req.AddCookie(&http.Cookie{Name: "login#state1#1000", Value: "v"})
	rec := httptest.NewRecorder()

	app.clearAllLoginCookies(app.HTTPContext(rec, req))

	cookies := loginStateSetCookies(t, rec)
	if len(cookies) != 1 || cookies[0].Domain != appLevelRootDomain || cookies[0].MaxAge >= 0 {
		t.Errorf("Expected the login state cookie to be cleared on the root domain, got %v", cookies)
	}
}

func TestLogoutURL_AppLevel_UnresolvedTenant(t *testing.T) {
	tests := []struct {
		name                string
		useTenantSubdomains bool
		appLevel            *bool
		customLoginPageURL  string
		config              LogoutConfig
		expected            string
	}{
		{"login URL without tenant subdomain", true, nil, "", NewLogoutConfig(), "https://" + appLevelRootDomain + "/api/auth/login"},
		{"login URL as is without tenant subdomains", false, nil, "", NewLogoutConfig(), "https://" + appLevelRootDomain + "/api/auth/login"},
		{"redirect URL takes precedence", true, nil, "", NewLogoutConfig(WithRedirectURL("https://redirect.example.com")), "https://redirect.example.com"},
		{"custom login page has no effect", true, nil, "https://custom.example.com/login", NewLogoutConfig(), "https://" + appLevelRootDomain + "/api/auth/login"},
		{"app login page when disabled", true, boolPtr(false), "", NewLogoutConfig(), "https://" + appLevelVanityDomain + "/login?client_id=test-client"},
		{"custom login page when disabled", true, boolPtr(false), "https://custom.example.com/login", NewLogoutConfig(), "https://custom.example.com/login?client_id=test-client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := newAppLevelAuth(t, tt.useTenantSubdomains, tt.appLevel, tt.customLoginPageURL)
			req := newMockHTTPRequest()
			req.host = appLevelRootDomain

			logoutURL, err := auth.LogoutURL(req, tt.config)
			if err != nil {
				t.Fatalf("LogoutURL returned error: %v", err)
			}
			if logoutURL != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, logoutURL)
			}
		})
	}
}

func TestConfigResolver_TenantPlaceholderValidation(t *testing.T) {
	tests := []struct {
		name        string
		loginURL    string
		redirectURI string
		expectedErr string
	}{
		{"both with placeholder", "https://{tenant_name}.myapp.com/login", "https://{tenant_name}.myapp.com/callback", ""},
		{"neither with placeholder", "https://myapp.com/login", "https://myapp.com/callback", ""},
		{"only login URL", "https://{tenant_name}.myapp.com/login", "https://myapp.com/callback", "the [redirect_uri] must contain the"},
		{"only redirect URI", "https://myapp.com/login", "https://{tenant_name}.myapp.com/callback", "the [redirect_uri] cannot contain the"},
		{"not leftmost", "https://app.{tenant_name}.myapp.com/login", "https://{tenant_name}.myapp.com/callback", "the [login_url] can only contain the"},
		{"in path", "https://{tenant_name}.myapp.com/login", "https://myapp.com/{tenant_name}/callback", "the [redirect_uri] can only contain the"},
		{"twice", "https://{tenant_name}.myapp.com/{tenant_name}/login", "https://{tenant_name}.myapp.com/callback", "the [login_url] can only contain the"},
		{"tenant_domain is not a placeholder", "https://{tenant_domain}.myapp.com/login", "https://{tenant_name}.myapp.com/callback", "the [redirect_uri] cannot contain the"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := NewAuthConfig("cid", "csecret", "app.wristband.dev", WithAutoConfigureDisabled(tt.loginURL, tt.redirectURI))
			_, err := NewConfigResolver(authConfig)
			if tt.expectedErr == "" {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("Expected error containing %q, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestConfigResolver_DerivedAndAppLevelConfigs(t *testing.T) {
	authConfig := NewAuthConfig("cid", "csecret", "app.wristband.dev",
		WithAutoConfigureDisabled("http://{tenant_name}.localhost:6001/api/auth/login", "http://{tenant_name}.localhost:6001/api/auth/callback"))
	resolver, err := NewConfigResolver(authConfig)
	if err != nil {
		t.Fatalf("NewConfigResolver returned error: %v", err)
	}
	if got := resolver.GetParseTenantFromRootDomain(); got != "localhost" {
		t.Errorf("Expected root domain %q, got %q", "localhost", got)
	}
	if got, _ := resolver.GetFallbackLoginURL(); got != "http://localhost:6001/api/auth/login" {
		t.Errorf("Expected fallback login URL %q, got %q", "http://localhost:6001/api/auth/login", got)
	}
	if !resolver.GetApplicationAuthorizationRequestsEnabled() {
		t.Error("Expected application-level authorization requests to default to enabled")
	}

	disabledConfig := NewAuthConfig("cid", "csecret", "app.wristband.dev",
		WithAutoConfigureDisabled("https://myapp.com/login", "https://myapp.com/callback"),
		WithApplicationAuthorizationRequestsEnabled(false))
	disabledResolver, err := NewConfigResolver(disabledConfig)
	if err != nil {
		t.Fatalf("NewConfigResolver returned error: %v", err)
	}
	if disabledResolver.GetApplicationAuthorizationRequestsEnabled() {
		t.Error("Expected application-level authorization requests to be disabled")
	}
	if got := disabledResolver.GetParseTenantFromRootDomain(); got != "" {
		t.Errorf("Expected no root domain without the placeholder, got %q", got)
	}
}
