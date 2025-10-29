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
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
		logoutRedirectURI:    "https://example.com/home",
		logoutStateParameter: "test-state-123",
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

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
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
		},
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_custom_domain", "custom.tenant.com")

	logoutURL := auth.LogoutUrl(req)

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
	auth := WristbandAuth{
		Client:            ConfidentialClient{ClientID: "test-client-id"},
		Domains:           AppDomains{WristbandDomain: "test.wristband.com"},
		logoutRedirectURI: "https://example.com/goodbye",
	}

	req := newMockHTTPRequest() // No tenant domain parameters

	logoutURL := auth.LogoutUrl(req)

	expected := "https://example.com/goodbye"
	if logoutURL != expected {
		t.Errorf("Expected logout URL %s, got %s", expected, logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_NoTenantedHost_NoLogoutRedirectURI(t *testing.T) {
	auth := WristbandAuth{
		Client:  ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{WristbandDomain: "test.wristband.com"},
	}

	req := newMockHTTPRequest() // No tenant domain parameters

	logoutURL := auth.LogoutUrl(req)

	expected := "https://test.wristband.com/login?client_id=test-client-id"
	if logoutURL != expected {
		t.Errorf("Expected logout URL %s, got %s", expected, logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_MinimalParameters(t *testing.T) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "minimal-client"},
		Domains: AppDomains{
			WristbandDomain: "minimal.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "minimal-tenant",
				separator:    "-",
			},
		},
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "minimal-tenant")

	logoutURL := auth.LogoutUrl(req)

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

func TestWristbandAuth_LogoutURL_EmptyClientID(t *testing.T) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: ""},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

	// Parse the URL to verify components
	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("Failed to parse logout URL: %v", err)
	}

	// Verify empty client_id is still included
	query := parsedURL.Query()
	if !query.Has("client_id") {
		t.Error("Expected client_id parameter to be present")
	}
	if query.Get("client_id") != "" {
		t.Errorf("Expected empty client_id, got %s", query.Get("client_id"))
	}
}

func TestWristbandAuth_LogoutURL_SpecialCharactersInParameters(t *testing.T) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client@special"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
		logoutRedirectURI:    "https://example.com/path?param=value&other=test",
		logoutStateParameter: "state with spaces & symbols!",
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

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
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain:                 "test.wristband.com",
			IsApplicationCustomDomainActive: true,
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    ".",
			},
		},
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

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
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain:           "test.wristband.com",
			RootDomain:                "example.com",
			ParseTenantFromRootDomain: true,
		},
	}

	req := newMockHTTPRequest()
	req.host = "tenant1.example.com"

	logoutURL := auth.LogoutUrl(req)

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
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
		},
	}

	req := newMockHTTPRequest()
	// Both parameters present - custom domain should take precedence
	req.queryValues.Set("tenant_domain", "tenant1")
	req.queryValues.Set("tenant_custom_domain", "custom.tenant.com")

	logoutURL := auth.LogoutUrl(req)

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
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
		logoutRedirectURI:    "https://example.com/logout?success=true&message=logged out",
		logoutStateParameter: "state=test&value=123",
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

	// Verify URL contains properly encoded parameters
	if !strings.Contains(logoutURL, "redirect_url=https%3A%2F%2Fexample.com%2Flogout%3Fsuccess%3Dtrue%26message%3Dlogged+out") {
		t.Error("redirect_url should be properly URL encoded")
	}
	if !strings.Contains(logoutURL, "state=state%3Dtest%26value%3D123") {
		t.Error("state should be properly URL encoded")
	}
}

func TestWristbandAuth_LogoutURL_EmptyTenantDomain(t *testing.T) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
		},
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "") // Empty tenant domain

	logoutURL := auth.LogoutUrl(req)

	// With empty tenant domain, it should still create a tenanted host with empty tenant
	// This results in "-test.wristband.com"
	expected := "https://-test.wristband.com/api/v1/logout?client_id=test-client-id"
	if logoutURL != expected {
		t.Errorf("Expected logout URL %s, got %s", expected, logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_NilRequest(t *testing.T) {
	auth := WristbandAuth{
		Client:            ConfidentialClient{ClientID: "test-client-id"},
		Domains:           AppDomains{WristbandDomain: "test.wristband.com"},
		logoutRedirectURI: "https://example.com/home",
	}

	// This would panic in real usage, but demonstrates the method's dependency on HTTPRequest
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling LogoutUrl with nil request")
		}
	}()

	auth.LogoutUrl(nil)
}

func TestWristbandAuth_LogoutURL_LongParameters(t *testing.T) {
	// Test with very long parameter values
	longClientID := strings.Repeat("a", 1000)
	longRedirectURI := "https://example.com/" + strings.Repeat("path/", 100)
	longState := strings.Repeat("state", 200)

	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: longClientID},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
		logoutRedirectURI:    longRedirectURI,
		logoutStateParameter: longState,
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

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

func TestWristbandAuth_LogoutURL_EmptyWristbandDomain(t *testing.T) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "", // Empty domain
		},
	}

	req := newMockHTTPRequest()

	logoutURL := auth.LogoutUrl(req)

	// Should still work but result in malformed URL
	expected := "https:///login?client_id=test-client-id"
	if logoutURL != expected {
		t.Errorf("Expected logout URL %s, got %s", expected, logoutURL)
	}
}

func TestWristbandAuth_LogoutURL_DefaultLogoutEndpoint(t *testing.T) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	logoutURL := auth.LogoutUrl(req)

	// Verify the default logout endpoint is used
	if !strings.Contains(logoutURL, DefaultLogoutEndpoint) {
		t.Errorf("Expected logout URL to contain %s, got %s", DefaultLogoutEndpoint, logoutURL)
	}
}

// Benchmark tests

func BenchmarkWristbandAuth_LogoutURL_WithTenant(b *testing.B) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
			DefaultDomains: &TenantDomains{
				TenantDomain: "tenant1",
				separator:    "-",
			},
		},
		logoutRedirectURI:    "https://example.com/home",
		logoutStateParameter: "test-state-123",
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_domain", "tenant1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.LogoutUrl(req)
	}
}

func BenchmarkWristbandAuth_LogoutURL_NoTenant(b *testing.B) {
	auth := WristbandAuth{
		Client:            ConfidentialClient{ClientID: "test-client-id"},
		Domains:           AppDomains{WristbandDomain: "test.wristband.com"},
		logoutRedirectURI: "https://example.com/home",
	}

	req := newMockHTTPRequest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.LogoutUrl(req)
	}
}

func BenchmarkWristbandAuth_LogoutURL_CustomDomain(b *testing.B) {
	auth := WristbandAuth{
		Client: ConfidentialClient{ClientID: "test-client-id"},
		Domains: AppDomains{
			WristbandDomain: "test.wristband.com",
		},
		logoutRedirectURI:    "https://example.com/home",
		logoutStateParameter: "test-state-123",
	}

	req := newMockHTTPRequest()
	req.queryValues.Set("tenant_custom_domain", "custom.tenant.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.LogoutUrl(req)
	}
}
