package goauth

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// TenantNameToken is the token used to represent tenant subdomains in URLs
	TenantNameToken = "{tenant_name}"

	// TenantPlaceholderMessage is a string describing the placeholder.
	TenantPlaceholderMessage = `"{tenant_name}" placeholder`
)

// ConfigResolver resolves and validates Wristband authentication configuration,
// supporting both manual configuration and auto-configuration via the Wristband SDK configuration endpoint
type ConfigResolver struct {
	*AuthConfig
	wristbandAPI    ConfidentialClient
	sdkConfigCache  *SdkConfiguration
	configPromise   chan *SdkConfiguration
	configMutex     sync.Mutex
	fetchInProgress bool
}

// NewConfigResolver creates a new ConfigResolver with the provided AuthConfig
func NewConfigResolver(authConfig *AuthConfig) (*ConfigResolver, error) {
	if len(authConfig.Scopes) == 0 {
		authConfig.Scopes = DefaultScopes
	}

	if authConfig.TokenExpirationBuffer == 0 {
		authConfig.TokenExpirationBuffer = DefaultTokenExpirationBuffer
	}

	resolver := &ConfigResolver{
		AuthConfig:     authConfig,
		configPromise:  make(chan *SdkConfiguration, 1),
		sdkConfigCache: nil,
	}

	// Always validate required configs
	if err := resolver.validateRequiredAuthConfigs(); err != nil {
		return nil, err
	}

	resolver.wristbandAPI = authConfig.Client()
	if authConfig.AutoConfigureEnabled {
		// Only validate manually provided values when auto-configure is enabled
		if err := resolver.validatePartialURLAuthConfigs(); err != nil {
			return nil, err
		}
		if err := resolver.PreloadSdkConfig(); err != nil {
			return nil, err
		}
	} else {
		// Validate all URL configs if auto-configure is disabled
		if err := resolver.validateStrictURLAuthConfigs(); err != nil {
			return nil, err
		}
	}

	return resolver, nil
}

// PreloadSdkConfig preloads SDK configuration (eager loading)
func (cr *ConfigResolver) PreloadSdkConfig() error {
	_, err := cr.loadSdkConfig()
	return err
}

func (cr *ConfigResolver) loadSdkConfig() (*SdkConfiguration, error) {
	// Return cached config if available
	if cr.sdkConfigCache != nil {
		return cr.sdkConfigCache, nil
	}

	cr.configMutex.Lock()

	// Check again in case another goroutine loaded it while we were waiting
	if cr.sdkConfigCache != nil {
		cr.configMutex.Unlock()
		return cr.sdkConfigCache, nil
	}

	// If a fetch is already in progress, wait for it
	if cr.fetchInProgress {
		cr.configMutex.Unlock()
		select {
		case sdkConfig := <-cr.configPromise:
			cr.configMutex.Lock()
			cr.sdkConfigCache = sdkConfig
			cr.configMutex.Unlock()
			return sdkConfig, nil
		case <-time.After(30 * time.Second):
			cr.configMutex.Lock()
			cr.fetchInProgress = false
			cr.configMutex.Unlock()
			return nil, fmt.Errorf("timeout waiting for SDK configuration")
		}
	}

	// Start the fetch
	cr.fetchInProgress = true
	cr.configMutex.Unlock()

	go func() {
		sdkConfig, err := cr.fetchSdkConfiguration()
		if err != nil {
			cr.configMutex.Lock()
			cr.fetchInProgress = false
			cr.configMutex.Unlock()
			// Send error to channel - for now we'll just close it
			close(cr.configPromise)
			return
		}

		cr.configMutex.Lock()
		cr.sdkConfigCache = sdkConfig
		cr.fetchInProgress = false
		cr.configMutex.Unlock()

		select {
		case cr.configPromise <- sdkConfig:
		default:
			// No one is waiting, that's fine
		}
	}()

	// Wait for the result
	select {
	case sdkConfig := <-cr.configPromise:
		if sdkConfig == nil {
			return nil, fmt.Errorf("failed to load sdk configuration")
		}
		return sdkConfig, nil
	case <-time.After(30 * time.Second):
		cr.configMutex.Lock()
		cr.fetchInProgress = false
		cr.configMutex.Unlock()
		return nil, fmt.Errorf("timeout waiting for SDK configuration")
	}
}

// fetchSdkConfiguration fetches and validates the SDK configuration.
//
// Retrying transient failures (5xx responses and network errors) is handled one layer down by
// ConfidentialClient.GetSdkConfiguration -- see withRetry in retry.go. By the time an error
// surfaces here, any applicable retries have already been exhausted.
func (cr *ConfigResolver) fetchSdkConfiguration() (*SdkConfiguration, error) {
	sdkConfig, err := cr.wristbandAPI.GetSdkConfiguration()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SDK configuration: %w", err)
	}

	if err := cr.validateAllDynamicConfigs(sdkConfig); err != nil {
		return nil, fmt.Errorf("SDK configuration validation failed: %w", err)
	}

	return sdkConfig, nil
}

func (cr *ConfigResolver) validateRequiredAuthConfigs() error {
	if cr.ClientID == "" {
		return fmt.Errorf("the [client_id] config must have a value")
	}
	if cr.ClientSecret == "" {
		return fmt.Errorf("the [client_secret] config must have a value")
	}
	if cr.LoginStateSecret != "" && len(cr.LoginStateSecret) < 32 {
		return fmt.Errorf("the [login_state_secret] config must have a value of at least 32 characters")
	}
	if cr.WristbandApplicationVanityDomain == "" {
		return fmt.Errorf("the [wristband_application_vanity_domain] config must have a value")
	}
	if cr.TokenExpirationBuffer < 0 {
		return fmt.Errorf("the [token_expiration_buffer] config must be greater than or equal to 0")
	}
	return nil
}

func (cr *ConfigResolver) validateStrictURLAuthConfigs() error {
	if cr.SdkConfiguration == nil {
		return fmt.Errorf("the [sdk_configuration] config must have a value if auto-configure is disabled")
	}
	if cr.LoginURL == "" {
		return fmt.Errorf("the [login_url] config must have a value when auto-configure is disabled")
	}
	if cr.RedirectURI == "" {
		return fmt.Errorf("the [redirect_uri] config must have a value when auto-configure is disabled")
	}
	if err := validateTenantPlaceholderPosition("login_url", cr.LoginURL); err != nil {
		return err
	}
	if err := validateTenantPlaceholderPosition("redirect_uri", cr.RedirectURI); err != nil {
		return err
	}
	return validateMatchingTenantPlaceholders(cr.LoginURL, cr.RedirectURI, "")
}

// validatePartialURLAuthConfigs validates the manually provided URL configs when auto-configure is enabled.
// When only one of the two URLs is provided, the placeholder comparison happens in validateAllDynamicConfigs
// instead, once the other URL is available from the SDK Auto-Configuration Endpoint.
func (cr *ConfigResolver) validatePartialURLAuthConfigs() error {
	if cr.SdkConfiguration == nil {
		return nil
	}
	if cr.LoginURL != "" {
		if err := validateTenantPlaceholderPosition("login_url", cr.LoginURL); err != nil {
			return err
		}
	}
	if cr.RedirectURI != "" {
		if err := validateTenantPlaceholderPosition("redirect_uri", cr.RedirectURI); err != nil {
			return err
		}
	}
	if cr.LoginURL != "" && cr.RedirectURI != "" {
		return validateMatchingTenantPlaceholders(cr.LoginURL, cr.RedirectURI, "")
	}
	return nil
}

// validateTenantPlaceholderPosition checks that a URL only contains the {tenant_name} placeholder once, as the
// leftmost part of its hostname.
func validateTenantPlaceholderPosition(configName, rawURL string) error {
	if !isTenantPlaceholderPositionValid(rawURL) {
		return fmt.Errorf("the [%s] can only contain the %s once, as the leftmost part of its hostname", configName, TenantPlaceholderMessage)
	}
	return nil
}

// validateMatchingTenantPlaceholders checks that either both URLs contain the {tenant_name} placeholder or
// neither does. The qualifier (e.g. "resolved ") is added to the config names in the error message.
func validateMatchingTenantPlaceholders(loginURL, redirectURI, qualifier string) error {
	loginURLHasPlaceholder := strings.Contains(loginURL, TenantNameToken)
	redirectURIHasPlaceholder := strings.Contains(redirectURI, TenantNameToken)
	if loginURLHasPlaceholder && !redirectURIHasPlaceholder {
		return fmt.Errorf("the %s[redirect_uri] must contain the %s when the %s[login_url] contains it", qualifier, TenantPlaceholderMessage, qualifier)
	}
	if !loginURLHasPlaceholder && redirectURIHasPlaceholder {
		return fmt.Errorf("the %s[redirect_uri] cannot contain the %s when the %s[login_url] does not contain it", qualifier, TenantPlaceholderMessage, qualifier)
	}
	return nil
}

// validateAllDynamicConfigs validates the final resolved URL configs after the SDK Auto-Configuration Endpoint
// responds. When at least one of [login_url] and [redirect_uri] was provided manually, either both resolved URLs
// must contain the {tenant_name} placeholder or neither does. When both URLs come from the SDK Auto-Configuration
// Endpoint, their placeholders are trusted as-is.
func (cr *ConfigResolver) validateAllDynamicConfigs(sdkConfig *SdkConfiguration) error {
	// Use manual config values if provided, otherwise use SDK config values
	manualLoginURL := ""
	manualRedirectURI := ""
	if cr.SdkConfiguration != nil {
		manualLoginURL = cr.LoginURL
		manualRedirectURI = cr.RedirectURI
	}
	loginURL := manualLoginURL
	if loginURL == "" {
		loginURL = sdkConfig.LoginURL
	}
	redirectURI := manualRedirectURI
	if redirectURI == "" {
		redirectURI = sdkConfig.RedirectURI
	}

	// Validate that required fields are present in the SDK config response
	if loginURL == "" {
		return fmt.Errorf("SDK configuration response missing required field: login_url")
	}
	if redirectURI == "" {
		return fmt.Errorf("the [redirect_uri] could not be resolved. Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured")
	}

	if manualLoginURL != "" || manualRedirectURI != "" {
		return validateMatchingTenantPlaceholders(loginURL, redirectURI, "resolved ")
	}
	return nil
}

// Static configuration getters

// GetClientID returns the client ID.
func (cr *ConfigResolver) GetClientID() string {
	return cr.ClientID
}

// getLoginStateSecret returns the login state secret.
func (cr *ConfigResolver) getLoginStateSecret() string {
	if cr.LoginStateSecret != "" {
		return cr.LoginStateSecret
	}
	return cr.ClientSecret
}

// GetWristbandApplicationVanityDomain returns the wristband application vanity domain.
func (cr *ConfigResolver) GetWristbandApplicationVanityDomain() string {
	return cr.WristbandApplicationVanityDomain
}

// GetDangerouslyDisableSecureCookies returns whether dangerously disable secure cookies is enabled.
func (cr *ConfigResolver) GetDangerouslyDisableSecureCookies() bool {
	return cr.DangerouslyDisableSecureCookies
}

// GetScopes returns the scopes.
func (cr *ConfigResolver) GetScopes() []string {
	return cr.Scopes
}

// GetAutoConfigureEnabled returns whether auto-configure is enabled.
func (cr *ConfigResolver) GetAutoConfigureEnabled() bool {
	return cr.AutoConfigureEnabled
}

// GetTokenExpirationBuffer returns the token expiration buffer.
func (cr *ConfigResolver) GetTokenExpirationBuffer() int {
	return cr.TokenExpirationBuffer
}

// Dynamic configuration getters

// GetCustomApplicationLoginPageURL returns the custom application login page URL.
func (cr *ConfigResolver) GetCustomApplicationLoginPageURL() (string, error) {
	// 1. Check if manually provided in authConfig
	if cr.SdkConfiguration != nil {
		return cr.CustomApplicationLoginPageURL, nil
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			return "", err
		}
		return sdkConfig.CustomApplicationLoginPageURL, nil
	}

	// 3. Default fallback
	return "", nil
}

// GetIsApplicationCustomDomainActive returns whether the application custom domain is active.
func (cr *ConfigResolver) GetIsApplicationCustomDomainActive() bool {
	// 1. Check if manually provided in authConfig
	if cr.SdkConfiguration != nil {
		return cr.IsApplicationCustomDomainActive
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			// TODO Log
			return false
		}
		return sdkConfig.IsApplicationCustomDomainActive
	}

	// 3. Default fallback
	return false
}

// MustLoginURL returns the login URL or panics if not found (should not happen if validated).
func (cr *ConfigResolver) MustLoginURL() string {
	url, _ := cr.GetLoginURL()
	return url
}

// GetLoginURL returns the login URL.
func (cr *ConfigResolver) GetLoginURL() (string, error) {
	// 1. Check if manually provided in authConfig
	if cr.SdkConfiguration != nil && cr.LoginURL != "" {
		return cr.LoginURL, nil
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			return "", err
		}
		return sdkConfig.LoginURL, nil
	}

	// 3. This should not happen if validation is done properly
	return "", fmt.Errorf("the [login_url] config must have a value")
}

// GetParseTenantFromRootDomain returns the root domain used for parsing tenant subdomains. It is derived from the
// login URL by removing the {tenant_name} subdomain, and is empty when tenant subdomains are not in use.
func (cr *ConfigResolver) GetParseTenantFromRootDomain() string {
	// 1. Derive from the manually provided login URL
	if cr.SdkConfiguration != nil && cr.LoginURL != "" {
		return deriveTenantRootDomain(cr.LoginURL)
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			// TODO Log
			return ""
		}
		return sdkConfig.LoginURLTenantDomainSuffix
	}

	// 3. Default fallback
	return ""
}

func (cr *ConfigResolver) GetRedirectURI() string {
	// 1. Check if manually provided in authConfig
	if cr.SdkConfiguration != nil && cr.RedirectURI != "" {
		return cr.RedirectURI
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		if sdkConfig, err := cr.loadSdkConfig(); err == nil {
			return sdkConfig.RedirectURI
		}
	}

	// 3. Default fallback
	return ""
}

// GetApplicationAuthorizationRequestsEnabled returns whether application-level authorization requests are enabled.
// It defaults to true.
func (cr *ConfigResolver) GetApplicationAuthorizationRequestsEnabled() bool {
	// 1. Check if manually provided in authConfig
	if cr.applicationAuthorizationRequestsEnabled != nil {
		return *cr.applicationAuthorizationRequestsEnabled
	}
	if cr.SdkConfiguration != nil && cr.ApplicationAuthorizationRequestsEnabled != nil {
		return *cr.ApplicationAuthorizationRequestsEnabled
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err == nil && sdkConfig.ApplicationAuthorizationRequestsEnabled != nil {
			return *sdkConfig.ApplicationAuthorizationRequestsEnabled
		}
	}

	// 3. Default fallback
	return true
}

// GetFallbackLoginURL returns the login URL without the {tenant_name} subdomain, which is used when a tenant
// cannot be resolved and application-level authorization requests are enabled.
func (cr *ConfigResolver) GetFallbackLoginURL() (string, error) {
	// 1. Derive from the manually provided login URL
	if cr.SdkConfiguration != nil && cr.LoginURL != "" {
		return deriveFallbackLoginURL(cr.LoginURL), nil
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			return "", err
		}
		return sdkConfig.FallbackLoginURL, nil
	}

	// 3. Default fallback
	return "", nil
}
