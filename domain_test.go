package goauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAuthConfig_Defaults(t *testing.T) {
	cfg := NewAuthConfig("cid", "csecret", "app.wristband.dev")

	if cfg.ClientID != "cid" {
		t.Errorf("Expected ClientID %q, got %q", "cid", cfg.ClientID)
	}
	if cfg.ClientSecret != "csecret" {
		t.Errorf("Expected ClientSecret %q, got %q", "csecret", cfg.ClientSecret)
	}
	if cfg.WristbandApplicationVanityDomain != "app.wristband.dev" {
		t.Errorf("Expected domain %q, got %q", "app.wristband.dev", cfg.WristbandApplicationVanityDomain)
	}
	if !cfg.AutoConfigureEnabled {
		t.Error("AutoConfigureEnabled should default to true")
	}
	if cfg.TokenExpirationBuffer != DefaultTokenExpirationBuffer {
		t.Errorf("Expected TokenExpirationBuffer %d, got %d", DefaultTokenExpirationBuffer, cfg.TokenExpirationBuffer)
	}
	if len(cfg.Scopes) != len(DefaultScopes) || !hasAll(cfg.Scopes, DefaultScopes...) {
		t.Errorf("Expected %d default scopes, got %d", len(DefaultScopes), len(cfg.Scopes))
	}
	if cfg.LoginStateSecret == "" {
		t.Error("LoginStateSecret should be auto-generated when not provided")
	}
}

func TestNewAuthConfig_WithOptions(t *testing.T) {
	cfg := NewAuthConfig("cid", "csecret", "app.wristband.dev",
		WithAutoConfigureDisabled("https://login.example.com", "https://app.example.com/callback"),
		WithParseTenantFromRootDomain("example.com"),
		WithLoginStateSecret("my-32-byte-secret-for-encryption"),
		WithTokenExpirationBuffer(120),
		WithConfigScopes([]string{"openid", "profile"}),
		WithDangerouslyDisableSecureCookies(),
	)

	if cfg.AutoConfigureEnabled {
		t.Error("AutoConfigureEnabled should be false after WithAutoConfigureDisabled")
	}
	if cfg.SdkConfiguration == nil {
		t.Fatal("SdkConfiguration should not be nil")
	}
	if cfg.LoginURL != "https://login.example.com" {
		t.Errorf("Expected LoginURL %q, got %q", "https://login.example.com", cfg.LoginURL)
	}
	if cfg.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("Expected RedirectURI %q, got %q", "https://app.example.com/callback", cfg.RedirectURI)
	}
	if cfg.ParseTenantFromRootDomain != "example.com" {
		t.Errorf("Expected ParseTenantFromRootDomain %q, got %q", "example.com", cfg.ParseTenantFromRootDomain)
	}
	if cfg.LoginStateSecret != "my-32-byte-secret-for-encryption" {
		t.Errorf("Expected custom LoginStateSecret, got %q", cfg.LoginStateSecret)
	}
	if cfg.TokenExpirationBuffer != 120 {
		t.Errorf("Expected TokenExpirationBuffer 120, got %d", cfg.TokenExpirationBuffer)
	}
	if len(cfg.Scopes) != 2 || !hasAll(cfg.Scopes, "openid", "profile") {
		t.Errorf("Expected scopes [openid profile], got %v", cfg.Scopes)
	}
	if !cfg.DangerouslyDisableSecureCookies {
		t.Error("DangerouslyDisableSecureCookies should be true")
	}
}

func TestWithAutoConfigurableConfigs(t *testing.T) {
	sdkCfg := SdkConfiguration{
		LoginURL:    "https://tenant.example.com/login",
		RedirectURI: "https://app.example.com/callback",
	}
	cfg := NewAuthConfig("cid", "csecret", "app.wristband.dev",
		WithAutoConfigurableConfigs(sdkCfg),
	)

	if cfg.SdkConfiguration == nil {
		t.Fatal("SdkConfiguration should be set")
	}
	if cfg.SdkConfiguration.LoginURL != sdkCfg.LoginURL {
		t.Errorf("Expected LoginURL %q, got %q", sdkCfg.LoginURL, cfg.SdkConfiguration.LoginURL)
	}
}

func TestRoundTripperFunc(t *testing.T) {
	called := false
	fn := RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})

	req := httptest.NewRequest("GET", "http://example.com", nil)
	resp, err := fn.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	if !called {
		t.Error("RoundTripper function was not called")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestAuthConfig_Client(t *testing.T) {
	cfg := NewAuthConfig("test-cid", "test-csecret", "app.wristband.dev")

	client := cfg.Client()

	if client.ClientID != "test-cid" {
		t.Errorf("Expected ClientID %q, got %q", "test-cid", client.ClientID)
	}
	if client.ClientSecret != "test-csecret" {
		t.Errorf("Expected ClientSecret %q, got %q", "test-csecret", client.ClientSecret)
	}
	if client.WristbandApplicationVanityDomain != "app.wristband.dev" {
		t.Errorf("Expected domain %q, got %q", "app.wristband.dev", client.WristbandApplicationVanityDomain)
	}
	if client.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
}

func TestRequestTenantName_FromQueryParam(t *testing.T) {
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
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_name", "acme")

	tenantName, err := auth.RequestTenantName(req)
	if err != nil {
		t.Fatalf("RequestTenantName returned error: %v", err)
	}
	if tenantName != "acme" {
		t.Errorf("Expected %q, got %q", "acme", tenantName)
	}
}

func TestRequestTenantName_FromSubdomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		ParseTenantFromRootDomain:        "example.com",
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://{tenant_domain}.app.wristband.dev/login",
			RedirectURI: "https://{tenant_domain}.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := newMockHTTPRequest()
	req.host = "acme.example.com"

	tenantName, err := auth.RequestTenantName(req)
	if err != nil {
		t.Fatalf("RequestTenantName returned error: %v", err)
	}
	if tenantName != "acme" {
		t.Errorf("Expected %q, got %q", "acme", tenantName)
	}
}

func TestRequestTenantName_SubdomainWithPort(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		ParseTenantFromRootDomain:        "example.com",
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://{tenant_domain}.app.wristband.dev/login",
			RedirectURI: "https://{tenant_domain}.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := newMockHTTPRequest()
	req.host = "acme.example.com:8080"

	tenantName, err := auth.RequestTenantName(req)
	if err != nil {
		t.Fatalf("RequestTenantName returned error: %v", err)
	}
	if tenantName != "acme" {
		t.Errorf("Expected %q, got %q", "acme", tenantName)
	}
}

func TestRequestTenantName_InvalidSubdomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		ParseTenantFromRootDomain:        "example.com",
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://{tenant_domain}.app.wristband.dev/login",
			RedirectURI: "https://{tenant_domain}.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := newMockHTTPRequest()
	req.host = "acme.otherdomain.com"

	_, err = auth.RequestTenantName(req)
	if err == nil {
		t.Error("Expected error for host not matching root domain")
	}
}

func TestRequestCustomTenantName(t *testing.T) {
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
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	t.Run("present", func(t *testing.T) {
		req := newMockHTTPRequest()
		req.queryValues.Set("tenant_custom_domain", "custom.acme.com")
		name, ok := auth.RequestCustomTenantName(req)
		if !ok {
			t.Error("Expected ok=true when tenant_custom_domain is present")
		}
		if name != "custom.acme.com" {
			t.Errorf("Expected %q, got %q", "custom.acme.com", name)
		}
	})

	t.Run("absent", func(t *testing.T) {
		req := newMockHTTPRequest()
		_, ok := auth.RequestCustomTenantName(req)
		if ok {
			t.Error("Expected ok=false when tenant_custom_domain is absent")
		}
	})
}
