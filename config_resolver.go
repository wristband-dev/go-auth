package goauth

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// TenantDomainToken is the token used to represent tenant domains in URLs
const TenantDomainToken = "{tenant_domain}"

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
		return sdkConfig, nil
	case <-time.After(30 * time.Second):
		cr.configMutex.Lock()
		cr.fetchInProgress = false
		cr.configMutex.Unlock()
		return nil, fmt.Errorf("timeout waiting for SDK configuration")
	}
}

func (cr *ConfigResolver) fetchSdkConfiguration() (*SdkConfiguration, error) {
	var lastError error

	for attempt := 1; attempt <= MaxFetchAttempts; attempt++ {
		sdkConfig, err := cr.wristbandAPI.GetSdkConfiguration()
		if err == nil {
			if err := cr.validateAllDynamicConfigs(sdkConfig); err != nil {
				return nil, fmt.Errorf("SDK configuration validation failed: %w", err)
			}
			return sdkConfig, nil
		}

		lastError = err

		if attempt == MaxFetchAttempts {
			break
		}

		// Wait before retrying
		time.Sleep(time.Duration(AttemptDelayMs) * time.Millisecond)
	}

	return nil, fmt.Errorf("failed to fetch SDK configuration after %d attempts: %w", MaxFetchAttempts, lastError)
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

	return cr.validateTenantDomainTokens()
}

func (cr *ConfigResolver) validatePartialURLAuthConfigs() error {
	return cr.validateTenantDomainTokens()
}

func (cr *ConfigResolver) validateTenantDomainTokens() error {
	if cr.ParseTenantFromRootDomain != "" {
		if !strings.Contains(cr.LoginURL, TenantDomainToken) {
			return fmt.Errorf("the [login_url] must contain the \"%s\" token when using the [parse_tenant_from_root_domain] config", TenantDomainToken)
		}
		if !strings.Contains(cr.RedirectURI, TenantDomainToken) {
			return fmt.Errorf("the [redirect_uri] must contain the \"%s\" token when using the [parse_tenant_from_root_domain] config", TenantDomainToken)
		}
	} else if cr.SdkConfiguration != nil {
		if strings.Contains(cr.LoginURL, TenantDomainToken) {
			return fmt.Errorf("the [login_url] cannot contain the \"%s\" token when the [parse_tenant_from_root_domain] is absent", TenantDomainToken)
		}
		if strings.Contains(cr.RedirectURI, TenantDomainToken) {
			return fmt.Errorf("the [redirect_uri] cannot contain the \"%s\" token when the [parse_tenant_from_root_domain] is absent", TenantDomainToken)
		}
	}
	return nil
}

func (cr *ConfigResolver) validateAllDynamicConfigs(sdkConfig *SdkConfiguration) error {
	// Validate that required fields are present in the SDK config response
	if sdkConfig.LoginURL == "" {
		return fmt.Errorf("SDK configuration response missing required field: login_url")
	}
	if sdkConfig.RedirectURI == "" {
		return fmt.Errorf("SDK configuration response missing required field: redirect_uri")
	}

	// Use manual config values if provided, otherwise use SDK config values
	loginURL := ""
	redirectURI := ""
	if cr.SdkConfiguration != nil {
		loginURL = cr.LoginURL
		redirectURI = cr.RedirectURI
	}
	if loginURL == "" {
		loginURL = sdkConfig.LoginURL
	}
	if redirectURI == "" {
		redirectURI = sdkConfig.RedirectURI
	}

	parseTenantFromRootDomain := cr.ParseTenantFromRootDomain
	if parseTenantFromRootDomain == "" && sdkConfig.LoginURLTenantDomainSuffix != "" {
		parseTenantFromRootDomain = sdkConfig.LoginURLTenantDomainSuffix
	}

	// Validate the tenant domain token logic with final resolved values
	if parseTenantFromRootDomain != "" {
		if !strings.Contains(loginURL, TenantDomainToken) {
			return fmt.Errorf("the resolved [login_url] must contain the \"%s\" token when using [parse_tenant_from_root_domain]", TenantDomainToken)
		}
		if !strings.Contains(redirectURI, TenantDomainToken) {
			return fmt.Errorf("the resolved [redirect_uri] must contain the \"%s\" token when using [parse_tenant_from_root_domain]", TenantDomainToken)
		}
	} else {
		if strings.Contains(loginURL, TenantDomainToken) {
			return fmt.Errorf("the resolved [login_url] cannot contain the \"%s\" token when [parse_tenant_from_root_domain] is absent", TenantDomainToken)
		}
		if strings.Contains(redirectURI, TenantDomainToken) {
			return fmt.Errorf("the resolved [redirect_uri] cannot contain the \"%s\" token when [parse_tenant_from_root_domain] is absent", TenantDomainToken)
		}
	}

	return nil
}

// Static configuration getters

// GetClientID returns the client ID.
func (cr *ConfigResolver) GetClientID() string {
	return cr.ClientID
}

// GetClientSecret returns the client secret.
func (cr *ConfigResolver) GetClientSecret() string {
	return cr.ClientSecret
}

// GetLoginStateSecret returns the login state secret.
func (cr *ConfigResolver) GetLoginStateSecret() string {
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

// GetParseTenantFromRootDomain returns the parse tenant from root domain config.
func (cr *ConfigResolver) GetParseTenantFromRootDomain() string {
	// 1. Check if manually provided in authConfig
	if cr.ParseTenantFromRootDomain != "" {
		return cr.ParseTenantFromRootDomain
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

// GetRedirectURI returns the redirect URI.
func (cr *ConfigResolver) GetRedirectURI() string {
	// 1. Check if manually provided in authConfig
	if cr.SdkConfiguration != nil {
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
