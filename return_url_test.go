package goauth

import (
	"testing"
)

func TestDeriveFallbackLoginURL(t *testing.T) {
	tests := map[string]string{
		"https://{tenant_name}.myapp.com/api/auth/login":     "https://myapp.com/api/auth/login",
		"http://{tenant_name}.localhost:6001/api/auth/login": "http://localhost:6001/api/auth/login",
		"https://myapp.com/api/auth/login":                   "",
		"":                                                   "",
	}
	for loginURL, expected := range tests {
		if got := deriveFallbackLoginURL(loginURL); got != expected {
			t.Errorf("deriveFallbackLoginURL(%q) = %q, expected %q", loginURL, got, expected)
		}
	}
}

func TestDeriveTenantRootDomain(t *testing.T) {
	tests := map[string]string{
		"https://{tenant_name}.myapp.com/api/auth/login":     "myapp.com",
		"http://{tenant_name}.localhost:6001/api/auth/login": "localhost",
		"https://myapp.com/api/auth/login":                   "",
	}
	for loginURL, expected := range tests {
		if got := deriveTenantRootDomain(loginURL); got != expected {
			t.Errorf("deriveTenantRootDomain(%q) = %q, expected %q", loginURL, got, expected)
		}
	}
}

func TestIsTenantPlaceholderPositionValid(t *testing.T) {
	tests := map[string]bool{
		"https://myapp.com/api/auth/login":                    true,
		"https://{tenant_name}.myapp.com/api/auth/login":      true,
		"http://{tenant_name}.localhost:6001/api/auth/login":  true,
		"https://app.{tenant_name}.myapp.com/api/auth/login":  false,
		"https://myapp.com/{tenant_name}/api/auth/login":      false,
		"https://{tenant_name}/api/auth/login":                false,
		"https://{tenant_name}.myapp.com/{tenant_name}/login": false,
	}
	for rawURL, expected := range tests {
		if got := isTenantPlaceholderPositionValid(rawURL); got != expected {
			t.Errorf("isTenantPlaceholderPositionValid(%q) = %v, expected %v", rawURL, got, expected)
		}
	}
}

func TestValidateReturnURL(t *testing.T) {
	const (
		rootDomain = "myapp.com"
		tenantHost = "acme.myapp.com"
		tenantName = "acme"
	)

	tests := []struct {
		name       string
		returnURL  string
		scheme     string
		host       string
		appLevel   bool
		rootDomain string
		expected   string
	}{
		{"empty", "", "https", tenantHost, true, rootDomain, ""},
		{"relative path", "/settings?tab=1#top", "https", tenantHost, true, rootDomain, "/settings?tab=1#top"},
		{"request host", "https://acme.myapp.com/dashboard", "https", tenantHost, true, rootDomain, "https://acme.myapp.com/dashboard"},
		{"request host case-insensitive", "https://ACME.myapp.com/dashboard", "https", tenantHost, true, rootDomain, "https://ACME.myapp.com/dashboard"},
		{"root domain without rewrite when disabled", "https://myapp.com/dashboard", "https", tenantHost, false, rootDomain, "https://myapp.com/dashboard"},
		{"root domain rewritten when enabled", "https://myapp.com/dashboard?x=1#y", "https", tenantHost, true, rootDomain, "https://acme.myapp.com/dashboard?x=1#y"},
		{"root domain rewrite keeps port", "https://myapp.com:8443/home", "https", "acme.myapp.com:8443", true, rootDomain, "https://acme.myapp.com:8443/home"},
		{"no tenant subdomains", "https://myapp.com/dashboard", "https", "myapp.com", true, "", "https://myapp.com/dashboard"},
		{"relative path over http", "/home", "http", "acme.localhost:6001", true, "localhost", "/home"},
		{"off-site", "https://evil.com/phish", "https", tenantHost, true, rootDomain, ""},
		{"protocol-relative", "//evil.com/phish", "https", tenantHost, true, rootDomain, ""},
		{"backslash", `/\evil.com`, "https", tenantHost, true, rootDomain, ""},
		{"tab", "/\t/evil.com", "https", tenantHost, true, rootDomain, ""},
		{"leading newline", "\n//evil.com", "https", tenantHost, true, rootDomain, ""},
		{"other tenant", "https://other.myapp.com/dashboard", "https", tenantHost, true, rootDomain, ""},
		{"suffix trick", "https://myapp.com.evil.com/dashboard", "https", tenantHost, true, rootDomain, ""},
		{"scheme downgrade", "http://acme.myapp.com/dashboard", "https", tenantHost, true, rootDomain, ""},
		{"javascript", "javascript:alert(1)", "https", tenantHost, true, rootDomain, ""},
		{"opaque https", "https:evil.com", "https", tenantHost, true, rootDomain, ""},
		{"root domain without tenant subdomains", "https://myapp.com/dashboard", "https", "acme.example.com", true, "", ""},
		{"normalized", " /settings ", "https", tenantHost, true, rootDomain, "https://acme.myapp.com/settings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateReturnURL(tt.returnURL, tt.scheme, tt.host, tenantName, tt.appLevel, tt.rootDomain)
			if got != tt.expected {
				t.Errorf("validateReturnURL(%q) = %q, expected %q", tt.returnURL, got, tt.expected)
			}
		})
	}
}

func TestValidateReturnURL_RequiresTenantName(t *testing.T) {
	if got := validateReturnURL("/settings", "https", "acme.myapp.com", "", true, "myapp.com"); got != "" {
		t.Errorf("Expected empty return URL without a tenant name, got %q", got)
	}
}
