package goauth

import (
	"fmt"
	"net/http"
)

// Auth related constants
const (
	// DefaultTokenExpiryBuffer is the number of seconds.
	DefaultTokenExpiryBuffer = 60 // seconds

	// Default endpoints

	DefaultTokenEndpoint     = "/oauth2/token"
	DefaultAuthorizeEndpoint = "/oauth2/authorize"
	DefaultUserInfoEndpoint  = "/oauth2/userinfo"
	DefaultLogoutEndpoint    = "/logout"
	DefaultRevokeEndpoint    = "/oauth2/revoke"

	DefaultAPIPath = "/api/v1"
)

type (
	// AppDomains provides the application domain configuration.
	AppDomains struct {
		WristbandDomain string // WristbandApplicationVanityDomain
		// RootDomain is the root domain for the application.
		RootDomain string
		// DefaultDomains provides the default tenant domain configuration.
		DefaultDomains *TenantDomains
		// IsApplicationCustomDomainActive indicates if the application is using a custom domain.
		IsApplicationCustomDomainActive bool
		// ParseTenantFromRootDomain indicates if the tenant should be parsed from the request.
		ParseTenantFromRootDomain bool
		// CustomApplicationLoginPageURL is the URL of the custom login page for the application.
		CustomApplicationLoginPageURL string
	}

	// TenantDomains provides the tenant domain configuration.
	TenantDomains struct {
		TenantCustomDomain string `json:"tenant_custom_domain"`
		TenantDomain       string `json:"tenant_domain"`
		separator          string
	}
)

// Validate returns an error if the AppDomains configuration is invalid.
func (domains AppDomains) Validate() error {
	if domains.WristbandDomain == "" {
		return fmt.Errorf("wristband domain is required")
	}
	if domains.RootDomain == "" && domains.ParseTenantFromRootDomain {
		return fmt.Errorf("root domain is required")
	}
	return nil
}

// RequestTenantedHost returns the base path for a tenanted http request.
func (domains AppDomains) RequestTenantedHost(req *http.Request) string {
	return domains.TenantedHost(&StandardHTTP{req: req})
}

// TenantedHost returns the base path for a tenanted request.
func (domains AppDomains) TenantedHost(req HTTPRequest) string {
	return domains.RequestTenantDomains(req).BasePath(domains.WristbandDomain)
}

// RequestTenantDomains returns the tenant domain configuration for the url.Values.
func (domains AppDomains) RequestTenantDomains(req HTTPRequest) *TenantDomains {
	separator := "-"
	if domains.IsApplicationCustomDomainActive {
		separator = "."
	}
	if domains.ParseTenantFromRootDomain {
		host := req.Host()
		if host == "" {
			return domains.DefaultDomains
		}

		if len(domains.RootDomain) >= len(host) {
			return domains.DefaultDomains
		}
		// Extract the tenant domain from the host by removing the root domain and the dot before it.
		tenantDomain := host[:len(host)-len(domains.RootDomain)]
		if tenantDomain[len(tenantDomain)-1] == '.' {
			tenantDomain = tenantDomain[:len(tenantDomain)-1]
		}
		return &TenantDomains{
			TenantDomain: tenantDomain,
			separator:    separator,
		}
	}

	queryValues := req.Query()
	if queryValues == nil || !(queryValues.Has("tenant_custom_domain") || queryValues.Has("tenant_domain")) {
		return domains.DefaultDomains
	}

	return &TenantDomains{
		TenantCustomDomain: queryValues.Get("tenant_custom_domain"),
		TenantDomain:       queryValues.Get("tenant_domain"),
		separator:          separator,
	}
}

// BasePath returns the base API path for the tenant domains.
func (d *TenantDomains) BasePath(wristbandDomain string) string {
	if d == nil {
		return ""
	}
	if d.TenantCustomDomain != "" {
		return fmt.Sprintf("https://%s/api/v1", d.TenantCustomDomain)
	}
	separator := d.separator
	if separator == "" {
		separator = "-"
	}
	return fmt.Sprintf("https://%s%s%s/api/v1", d.TenantDomain, separator, wristbandDomain)
}
