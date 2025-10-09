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

// AuthConfig represents the configuration for Wristband authentication.
// This struct supports both manual configuration and auto-configuration via the Wristband SDK configuration endpoint.
type AuthConfig struct {
	// AutoConfigureEnabled tells the SDK to automatically set some configuration values by
	// calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations
	// will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default.
	// When disabled, if manual configurations are not provided, then an error will be thrown.
	AutoConfigureEnabled bool `json:"auto_configure_enabled"`

	// ClientID is the client ID for the application
	ClientID string `json:"client_id"`

	// ClientSecret is the client secret for the application
	ClientSecret string `json:"client_secret"`

	// LoginStateSecret is a secret (32 or more characters in length) used for encryption and decryption
	// of login state cookies. If not provided, it will default to using the client secret.
	// For enhanced security, it is recommended to provide a value that is unique from the client secret.
	LoginStateSecret string `json:"login_state_secret,omitempty"`

	// LoginURL is the URL for initiating the login request. This field is auto-configurable.
	// Required when auto-configure is disabled.
	LoginURL string `json:"login_url,omitempty"`

	// RedirectURI is the redirect URI for callback after authentication. This field is auto-configurable.
	// Required when auto-configure is disabled.
	RedirectURI string `json:"redirect_uri,omitempty"`

	// WristbandApplicationVanityDomain is the vanity domain of the Wristband application
	WristbandApplicationVanityDomain string `json:"wristband_application_vanity_domain"`

	// CustomApplicationLoginPageURL is the custom application login (tenant discovery) page URL
	// if you are self-hosting the application login/tenant discovery UI. This field is auto-configurable.
	CustomApplicationLoginPageURL string `json:"custom_application_login_page_url,omitempty"`

	// DangerouslyDisableSecureCookies if set to true, the "Secure" attribute will not be
	// included in any cookie settings. This should only be done when testing in local development.
	DangerouslyDisableSecureCookies bool `json:"dangerously_disable_secure_cookies"`

	// IsApplicationCustomDomainActive indicates whether an application-level custom domain
	// is active in your Wristband application. This field is auto-configurable.
	IsApplicationCustomDomainActive *bool `json:"is_application_custom_domain_active,omitempty"`

	// ParseTenantFromRootDomain is the root domain for your application from which to parse
	// out the tenant domain name. Indicates whether tenant subdomains are used for authentication.
	// This field is auto-configurable.
	ParseTenantFromRootDomain string `json:"parse_tenant_from_root_domain,omitempty"`

	// Scopes are the scopes required for authentication. Defaults to ["openid", "offline_access", "email"]
	Scopes []string `json:"scopes,omitempty"`

	// TokenExpirationBuffer is the buffer time (in seconds) to subtract from the access token's expiration time.
	// This causes the token to be treated as expired before its actual expiration, helping to avoid token
	// expiration during API calls. Defaults to 60 seconds.
	TokenExpirationBuffer int `json:"token_expiration_buffer"`
}

func NewAutoConfigureAuthConfig(clientID, clientSecret, wristbandDomain string) *AuthConfig {
	return &AuthConfig{
		AutoConfigureEnabled:             true,
		ClientID:                         clientID,
		ClientSecret:                     clientSecret,
		WristbandApplicationVanityDomain: wristbandDomain,
	}
}

func (ac AuthConfig) Client() ConfidentialClient {
	return ConfidentialClient{
		ClientID:                         ac.ClientID,
		httpClient:                       http.DefaultClient,
		ClientSecret:                     ac.ClientSecret,
		WristbandApplicationVanityDomain: ac.WristbandApplicationVanityDomain,
	}
}

// DefaultScopes returns the default OAuth scopes
var DefaultScopes = []string{"openid", "offline_access", "email"}

// DefaultTokenExpirationBuffer returns the default token expiration buffer in seconds
const DefaultTokenExpirationBuffer = 60

// SdkConfiguration represents the SDK configuration returned from Wristband's SDK Auto-Configuration Endpoint
type SdkConfiguration struct {
	// LoginURL is the URL for initiating the login request
	LoginURL string `json:"login_url"`

	// RedirectURI is the redirect URI for callback after authentication
	RedirectURI string `json:"redirect_uri"`

	// IsApplicationCustomDomainActive indicates whether an application-level custom domain is active
	IsApplicationCustomDomainActive bool `json:"is_application_custom_domain_active"`

	// CustomApplicationLoginPageURL is the custom application login (tenant discovery) page URL
	CustomApplicationLoginPageURL string `json:"custom_application_login_page_url,omitempty"`

	// LoginURLTenantDomainSuffix is the tenant domain suffix for the login URL when using tenant subdomains
	LoginURLTenantDomainSuffix string `json:"login_url_tenant_domain_suffix,omitempty"`
}
