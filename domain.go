package goauth

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/wristband-dev/go-auth/rand"
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

// AuthConfig represents the configuration for Wristband authentication.
// This struct supports both manual configuration and auto-configuration via the Wristband SDK configuration endpoint.
type AuthConfig struct {
	// REQUIRED

	// ClientID is the client ID for the application
	ClientID string `json:"client_id"`

	// ClientSecret is the client secret for the application
	ClientSecret string `json:"client_secret"`

	// WristbandApplicationVanityDomain is the vanity domain of the Wristband application
	WristbandApplicationVanityDomain string `json:"wristband_application_vanity_domain"`

	// OPTIONAL

	// LoginStateSecret is a secret (32 or more characters in length) used for encryption and decryption
	// of login state cookies. If not provided, it will default to using the client secret.
	// For enhanced security, it is recommended to provide a value that is unique from the client secret.
	LoginStateSecret string `json:"login_state_secret,omitempty"`

	// DangerouslyDisableSecureCookies if set to true, the "Secure" attribute will not be
	// included in any cookie settings. This should only be done when testing in local development.
	DangerouslyDisableSecureCookies bool `json:"dangerously_disable_secure_cookies"`

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

	// AutoConfigureEnabled tells the SDK to automatically set some configuration values by
	// calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations
	// will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default.
	// When disabled, if manual configurations are not provided, then an error will be thrown.
	AutoConfigureEnabled bool `json:"auto_configure_enabled"`

	// SdkConfiguration is the configuration that can be automatically configured using the Wristband configuration endpoint.
	// Required when AutoConfigureEnabled is false. If auto-configure is enabled, then the static values will take precedence.
	*SdkConfiguration

	httpClient *http.Client
}

// NewAuthConfig creates a new AuthConfig.
func NewAuthConfig(clientID, clientSecret, wristbandDomain string, opts ...AuthConfigOption) *AuthConfig {
	ac := &AuthConfig{
		AutoConfigureEnabled:             true,
		ClientID:                         clientID,
		ClientSecret:                     clientSecret,
		WristbandApplicationVanityDomain: wristbandDomain,
		Scopes:                           DefaultScopes,
		TokenExpirationBuffer:            DefaultTokenExpirationBuffer,
		httpClient:                       http.DefaultClient,
	}
	for _, opt := range opts {
		opt.apply(ac)
	}

	if len(ac.LoginStateSecret) == 0 {
		ac.LoginStateSecret = string(rand.GenerateRandomKey(32))
	}
	return ac
}

// AuthConfigOption is an option for the AuthConfig
type AuthConfigOption interface {
	apply(*AuthConfig)
}

// RoundTripperFunc is a function that implements the http.RoundTripper interface.
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements the http.RoundTripper interface.
func (fn RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type authConfigOptionFunc func(*AuthConfig)

func (f authConfigOptionFunc) apply(c *AuthConfig) { f(c) }

// WithHTTPClient allows setting a custom HTTP client for the remote requests.
func WithHTTPClient(client *http.Client) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.httpClient = client
	})
}

// WithAutoConfigureDisabled disables the auto-configure.
func WithAutoConfigureDisabled(loginURL, redirectURI string) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.AutoConfigureEnabled = false
		if c.SdkConfiguration == nil {
			c.SdkConfiguration = &SdkConfiguration{}
		}
		c.LoginURL = loginURL
		c.RedirectURI = redirectURI
	})
}

// WithAutoConfigurableConfigs is used to provide static values for auto-configure.
func WithAutoConfigurableConfigs(configuration SdkConfiguration) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.SdkConfiguration = &configuration
	})
}

// WithParseTenantFromRootDomain sets the ParseTenantFromRootDomain field.
func WithParseTenantFromRootDomain(rootDomain string) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.ParseTenantFromRootDomain = rootDomain
	})
}

// WithLoginStateSecret sets the LoginStateSecret field.
func WithLoginStateSecret(secret string) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.LoginStateSecret = secret
	})
}

// WithTokenExpirationBuffer sets the TokenExpirationBuffer field.
func WithTokenExpirationBuffer(buffer int) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.TokenExpirationBuffer = buffer
	})
}

// WithConfigScopes sets the Scopes field.
func WithConfigScopes(scopes []string) AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.Scopes = scopes
	})
}

// WithDangerouslyDisableSecureCookies disables secure cookies. Use for testing purposes only.
func WithDangerouslyDisableSecureCookies() AuthConfigOption {
	return authConfigOptionFunc(func(c *AuthConfig) {
		c.DangerouslyDisableSecureCookies = true
	})
}

// Client returns a new ConfidentialClient instance using the provided AuthConfig.
func (ac *AuthConfig) Client() ConfidentialClient {
	httpClient := &http.Client{
		Transport: RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				log.Printf("Error: %v\n", err)
			} else if resp.StatusCode != 200 {
				log.Printf("Invalid status code: %v\n", resp.Status)
			}
			return resp, nil
		}),
	}
	return ConfidentialClient{
		ClientID:                         ac.ClientID,
		httpClient:                       httpClient,
		ClientSecret:                     ac.ClientSecret,
		WristbandApplicationVanityDomain: ac.WristbandApplicationVanityDomain,
	}
}

// RequestTenantName returns the tenant name from the request.
func (auth WristbandAuth) RequestTenantName(req RequestURI) (string, error) {
	if parseTenantName := auth.configResolver.GetParseTenantFromRootDomain(); parseTenantName != "" {
		host := req.Host()
		if portIdx := strings.Index(host, ":"); portIdx > 0 {
			host = host[:portIdx]
		}
		if !strings.HasSuffix(host, parseTenantName) {
			return parseTenantName, fmt.Errorf("%s is not a valid tenant name", parseTenantName)
		}
		return strings.TrimSuffix(host, "."+parseTenantName), nil
	}
	return req.Query().Get("tenant_name"), nil
}

// RequestCustomTenantName returns the custom tenant name from the request.
func (auth WristbandAuth) RequestCustomTenantName(req RequestURI) (string, bool) {
	return req.Query().Get("tenant_custom_domain"), req.Query().Has("tenant_custom_domain")
}

func (auth WristbandAuth) separator() string {
	if auth.configResolver.GetIsApplicationCustomDomainActive() {
		return "."
	}
	return "-"
}

// DefaultScopes returns the default OAuth scopes
var DefaultScopes = []string{"openid", "offline_access", "email"}

// DefaultTokenExpirationBuffer returns the default token expiration buffer in seconds
const DefaultTokenExpirationBuffer = 60

// SdkConfiguration represents the SDK configuration returned from Wristband's SDK Auto-Configuration Endpoint
type SdkConfiguration struct {
	// REQUIRED

	// LoginURL is the URL for initiating the login request
	LoginURL string `json:"login_url"`

	// RedirectURI is the redirect URI for callback after authentication
	RedirectURI string `json:"redirect_uri"`

	// OPTIONAL

	// IsApplicationCustomDomainActive indicates whether an application-level custom domain is active
	IsApplicationCustomDomainActive bool `json:"is_application_custom_domain_active"`

	// CustomApplicationLoginPageURL is the custom application login (tenant discovery) page URL
	CustomApplicationLoginPageURL string `json:"custom_application_login_page_url,omitempty"`

	// LoginURLTenantDomainSuffix is the tenant domain suffix for the login URL when using tenant subdomains
	LoginURLTenantDomainSuffix string `json:"login_url_tenant_domain_suffix,omitempty"`
}
