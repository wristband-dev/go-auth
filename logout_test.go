package goauth

import (
	"net/url"
	"strings"
	"testing"
)

// Mock HTTPRequest for testing
type mockHTTPRequest struct {
	queryValues url.Values
	host        string
}

func newMockHTTPRequest() *mockHTTPRequest {
	return &mockHTTPRequest{
		queryValues: make(url.Values),
	}
}

func (m *mockHTTPRequest) Query() QueryValueResolver {
	return m.queryValues
}

func (m *mockHTTPRequest) Host() string {
	return m.host
}

// Test LogoutUrl method

func TestWristbandAuth_LogoutURL_WithTenantedHost(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName:  "tenant1",
		RedirectURL: "https://example.com/home",
		State:       "test-state-123",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify base URL
	expectedHost := "tenant1-test.wristband.com"
	if parsedURL.Host != expectedHost {
		t.Errorf("Expected host %s, got %s", expectedHost, parsedURL.Host)
	}

	// Verify path
	expectedPath := "/api/v1" + DefaultLogoutEndpoint
	if parsedURL.Path != expectedPath {
		t.Errorf("Expected path %s, got %s", expectedPath, parsedURL.Path)
	}

	// Verify query parameters
	query := parsedURL.Query()
	if query.Get("client_id") != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", query.Get("client_id"))
	}
	if query.Get("redirect_url") != "https://example.com/home" {
		t.Errorf("Expected redirect_url 'https://example.com/home', got %s", query.Get("redirect_url"))
	}
	if query.Get("state") != "test-state-123" {
		t.Errorf("Expected state 'test-state-123', got %s", query.Get("state"))
	}
}

func TestWristbandAuth_LogoutURL_WithCustomTenantDomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_custom_domain", "custom.tenant.com")

	logoutConfig := LogoutConfig{
		TenantCustomDomain: "custom.tenant.com",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify base URL uses custom domain
	expectedHost := "custom.tenant.com"
	if parsedURL.Host != expectedHost {
		t.Errorf("Expected host %s, got %s", expectedHost, parsedURL.Host)
	}

	// Verify path
	expectedPath := "/api/v1" + DefaultLogoutEndpoint
	if parsedURL.Path != expectedPath {
		t.Errorf("Expected path %s, got %s", expectedPath, parsedURL.Path)
	}

	// Verify query parameters
	query := parsedURL.Query()
	if query.Get("client_id") != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", query.Get("client_id"))
	}
}

func TestWristbandAuth_LogoutURL_NoTenantedHost_WithLogoutRedirectURI(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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

	req := newMockHTTPRequest() // No tenant domain parameters

	logoutConfig := LogoutConfig{
		RedirectURL: "https://example.com/goodbye",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// When tenant_domain is not in query params, RequestTenantName returns empty string (not error)
	// This creates a logout URL with empty tenant prefix and includes redirect_url as parameter
	expectedPrefix := "https://-test.wristband.com/api/v1/logout?client_id=test-client-id"
	if !strings.Contains(logoutURL, expectedPrefix) {
		t.Errorf("Expected logout URL to contain %s, got %s", expectedPrefix, logoutURL)
	}
	if !strings.Contains(logoutURL, "redirect_url=https%3A%2F%2Fexample.com%2Fgoodbye") {
		t.Errorf("Expected redirect_url parameter in logout URL, got %s", logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_NoTenantedHost_NoLogoutRedirectURI(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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

	req := newMockHTTPRequest() // No tenant domain parameters

	logoutConfig := LogoutConfig{} // No redirect URL or tenant info

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// When tenant_domain query param is not set, RequestTenantName returns empty string
	// which creates a URL with empty tenant prefix
	expected := "https://-test.wristband.com/api/v1/logout?client_id=test-client-id"
	if logoutURL != expected {
		t.Errorf("Expected logout URL %s, got %s", expected, logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_MinimalParameters(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "minimal-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "minimal.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://minimal.wristband.com/login",
			RedirectURI: "http://example.com/callback",
		},
	}
	resolver, _ := NewConfigResolver(authConfig)
	auth := WristbandAuth{
		Client:         ConfidentialClient{ClientID: "minimal-client"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "minimal-tenant")

	logoutConfig := LogoutConfig{
		TenantName: "minimal-tenant",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify only client_id is present
	query := parsedURL.Query()
	if query.Get("client_id") != "minimal-client" {
		t.Errorf("Expected client_id 'minimal-client', got %s", query.Get("client_id"))
	}
	if query.Get("redirect_url") != "" {
		t.Errorf("Expected no redirect_url, got %s", query.Get("redirect_url"))
	}
	if query.Get("state") != "" {
		t.Errorf("Expected no state, got %s", query.Get("state"))
	}
}

func TestWristbandAuth_LogoutURL_SpecialCharactersInParameters(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client@special",
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
		Client:         ConfidentialClient{ClientID: "test-client@special"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName:  "tenant1",
		RedirectURL: "https://example.com/path?param=value&other=test",
		State:       "state with spaces & symbols!",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify URL encoding is handled correctly
	query := parsedURL.Query()
	if query.Get("client_id") != "test-client@special" {
		t.Errorf("Expected client_id 'test-client@special', got %s", query.Get("client_id"))
	}
	if query.Get("redirect_url") != "https://example.com/path?param=value&other=test" {
		t.Errorf("Expected complex redirect_url, got %s", query.Get("redirect_url"))
	}
	if query.Get("state") != "state with spaces & symbols!" {
		t.Errorf("Expected complex state, got %s", query.Get("state"))
	}
}

func TestWristbandAuth_LogoutURL_WithApplicationCustomDomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:                        "https://test.wristband.com/login",
			RedirectURI:                     "http://example.com/callback",
			IsApplicationCustomDomainActive: true,
		},
	}
	resolver, _ := NewConfigResolver(authConfig)
	auth := WristbandAuth{
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName: "tenant1",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify base URL uses dot separator for custom domain
	expectedHost := "tenant1.test.wristband.com"
	if parsedURL.Host != expectedHost {
		t.Errorf("Expected host %s, got %s", expectedHost, parsedURL.Host)
	}
}

func TestWristbandAuth_LogoutURL_ParseTenantFromRootDomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "test.wristband.com",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		ParseTenantFromRootDomain:        "example.com",
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://{tenant_domain}.test.wristband.com/login", // Need {tenant_domain} token
			RedirectURI: "http://{tenant_domain}.example.com/callback",      // Need {tenant_domain} token
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := newMockHTTPRequest()
	req.host = "tenant1.example.com"

	logoutConfig := LogoutConfig{}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify base URL uses parsed tenant
	expectedHost := "tenant1-test.wristband.com"
	if parsedURL.Host != expectedHost {
		t.Errorf("Expected host %s, got %s", expectedHost, parsedURL.Host)
	}
}

func TestWristbandAuth_LogoutURL_BothTenantAndCustomDomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	// Both parameters present - custom domain should take precedence
	req.queryValues.Set("tenant_domain", "tenant1")
	req.queryValues.Set("tenant_custom_domain", "custom.tenant.com")

	logoutConfig := LogoutConfig{
		TenantName:         "tenant1",
		TenantCustomDomain: "custom.tenant.com",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify custom domain takes precedence
	expectedHost := "custom.tenant.com"
	if parsedURL.Host != expectedHost {
		t.Errorf("Expected host %s, got %s", expectedHost, parsedURL.Host)
	}
}

func TestWristbandAuth_LogoutURL_URLEncoding(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName:  "tenant1",
		RedirectURL: "https://example.com/logout?success=true&message=logged out",
		State:       "state=test&value=123",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Verify URL contains properly encoded parameters
	if !strings.Contains(logoutURL, "redirect_url=https%3A%2F%2Fexample.com%2Flogout%3Fsuccess%3Dtrue%26message%3Dlogged+out") {
		t.Error("redirect_url should be properly URL encoded")
	}
	if !strings.Contains(logoutURL, "state=state%3Dtest%26value%3D123") {
		t.Error("state should be properly URL encoded")
	}
}

func TestWristbandAuth_LogoutURL_EmptyTenantDomain(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "") // Empty tenant domain

	logoutConfig := LogoutConfig{
		TenantName: "",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// With empty tenant domain, it should still create a tenanted host with empty tenant
	// This results in "test.wristband.com"
	expected := "https://test.wristband.com/api/v1/logout?client_id=test-client-id"
	if logoutURL != expected {
		t.Errorf("Expected logout URL %s, got %s", expected, logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_NilRequest(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	logoutConfig := LogoutConfig{
		RedirectURL: "https://example.com/home",
	}

	// This would panic in real usage, but demonstrates the method's dependency on HTTPRequest
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling LogoutUrl with nil request")
		}
	}()

	auth.LogoutUrl(nil, logoutConfig)
}

func TestWristbandAuth_LogoutURL_LongParameters(t *testing.T) {
	// Test with very long parameter values
	longClientID := strings.Repeat("a", 1000)
	longRedirectURI := "https://example.com/" + strings.Repeat("path/", 100)
	longState := strings.Repeat("state", 100) // Reduced to stay under 512 chars (100 * 5 = 500)

	authConfig := &AuthConfig{
		ClientID:                         longClientID,
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
		Client:         ConfidentialClient{ClientID: longClientID},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName:  "tenant1",
		RedirectURL: longRedirectURI,
		State:       longState,
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Parse the URL to verify it's still valid
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL with long parameters: %v", err)
	}

	// Verify long parameters are preserved
	query := parsedURL.Query()
	if query.Get("client_id") != longClientID {
		t.Error("Long client_id not preserved correctly")
	}
	if query.Get("redirect_url") != longRedirectURI {
		t.Error("Long redirect_url not preserved correctly")
	}
	if query.Get("state") != longState {
		t.Error("Long state not preserved correctly")
	}
}

// Test edge cases and error conditions

func TestWristbandAuth_LogoutURL_DefaultLogoutEndpoint(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName: "tenant1",
	}

	logoutURL, err := auth.LogoutUrl(req, logoutConfig)
	if err != nil {
		t.Fatalf("Failed to generate logout URL: %v", err)
	}

	// Verify the default logout endpoint is used
	if !strings.Contains(logoutURL, DefaultLogoutEndpoint) {
		t.Errorf("Expected logout URL to contain %s, got %s", DefaultLogoutEndpoint, logoutURL)
	}
}

// Benchmark tests

func BenchmarkWristbandAuth_LogoutURL_WithTenant(b *testing.B) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutConfig := LogoutConfig{
		TenantName:  "tenant1",
		RedirectURL: "https://example.com/home",
		State:       "test-state-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = auth.LogoutUrl(req, logoutConfig)
	}
}

func BenchmarkWristbandAuth_LogoutURL_NoTenant(b *testing.B) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()

	logoutConfig := LogoutConfig{
		RedirectURL: "https://example.com/home",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = auth.LogoutUrl(req, logoutConfig)
	}
}

func BenchmarkWristbandAuth_LogoutURL_CustomDomain(b *testing.B) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client-id",
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
		Client:         ConfidentialClient{ClientID: "test-client-id"},
		configResolver: resolver,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_custom_domain", "custom.tenant.com")

	logoutConfig := LogoutConfig{
		TenantCustomDomain: "custom.tenant.com",
		RedirectURL:        "https://example.com/home",
		State:              "test-state-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = auth.LogoutUrl(req, logoutConfig)
	}
}
