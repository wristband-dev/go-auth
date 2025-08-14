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
	}

	// TenantDomains provides the tenant domain configuration.
	TenantDomains struct {
		TenantCustomDomain string `json:"tenant_custom_domain"`
		TenantDomain       string `json:"tenant_domain"`
	}
)

// Validate returns an error if the AppDomains configuration is invalid.
func (domains AppDomains) Validate() error {
	if domains.WristbandDomain == "" {
		return fmt.Errorf("wristband domain is required")
	}
	if domains.RootDomain == "" {
		return fmt.Errorf("root domain is required")
	}
	return nil
}

// RequestTenantedHost returns the base path for a tenanted http request.
func (domains AppDomains) RequestTenantedHost(req *http.Request) string {
	return domains.TenantedHost(req.URL.Query())
}

// TenantedHost returns the base path for a tenanted request.
func (domains AppDomains) TenantedHost(values QueryValueResolver) string {
	return domains.RequestTenantDomains(values).BasePath(domains.WristbandDomain)
}

// RequestTenantDomains returns the tenant domain configuration for the url.Values.
func (domains AppDomains) RequestTenantDomains(queryValues QueryValueResolver) *TenantDomains {
	if queryValues == nil || !(queryValues.Has("tenant_custom_domain") || queryValues.Has("tenant_domain")) {
		return domains.DefaultDomains
	}
	return &TenantDomains{
		TenantCustomDomain: queryValues.Get("tenant_custom_domain"),
		TenantDomain:       queryValues.Get("tenant_domain"),
	}
}

func (d *TenantDomains) BasePath(wristbandDomain string) string {
	if d == nil {
		return ""
	}
	if d.TenantCustomDomain != "" {
		return fmt.Sprintf("https://%s/api/v1", d.TenantCustomDomain)
	}
	return fmt.Sprintf("https://%s-%s/api/v1", d.TenantDomain, wristbandDomain)
}
