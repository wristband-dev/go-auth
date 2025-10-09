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
	authConfig      *AuthConfig
	wristbandApi    ConfidentialClient
	sdkConfigCache  *SdkConfiguration
	configPromise   chan *SdkConfiguration
	configMutex     sync.Mutex
	fetchInProgress bool
}

// NewConfigResolver creates a new ConfigResolver with the provided AuthConfig
func NewConfigResolver(authConfig *AuthConfig) (*ConfigResolver, error) {
	// Set defaults
	if !authConfig.AutoConfigureEnabled {
		// Auto-configure is disabled by default in the struct, but we want it enabled by default
		// based on the other SDKs pattern
		authConfig.AutoConfigureEnabled = true
	}

	if len(authConfig.Scopes) == 0 {
		authConfig.Scopes = DefaultScopes
	}

	if authConfig.TokenExpirationBuffer == 0 {
		authConfig.TokenExpirationBuffer = DefaultTokenExpirationBuffer
	}

	resolver := &ConfigResolver{
		authConfig:     authConfig,
		configPromise:  make(chan *SdkConfiguration, 1),
		sdkConfigCache: nil,
	}

	// Always validate required configs
	if err := resolver.validateRequiredAuthConfigs(); err != nil {
		return nil, err
	}

	if authConfig.AutoConfigureEnabled {
		// Only validate manually provided values when auto-configure is enabled
		if err := resolver.validatePartialUrlAuthConfigs(); err != nil {
			return nil, err
		}
	} else {
		// Validate all URL configs if auto-configure is disabled
		if err := resolver.validateStrictUrlAuthConfigs(); err != nil {
			return nil, err
		}
	}

	resolver.wristbandApi = authConfig.Client()
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
		sdkConfig, err := cr.wristbandApi.GetSdkConfiguration()
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
	if cr.authConfig.ClientID == "" {
		return fmt.Errorf("the [client_id] config must have a value")
	}
	if cr.authConfig.ClientSecret == "" {
		return fmt.Errorf("the [client_secret] config must have a value")
	}
	if cr.authConfig.LoginStateSecret != "" && len(cr.authConfig.LoginStateSecret) < 32 {
		return fmt.Errorf("the [login_state_secret] config must have a value of at least 32 characters")
	}
	if cr.authConfig.WristbandApplicationVanityDomain == "" {
		return fmt.Errorf("the [wristband_application_vanity_domain] config must have a value")
	}
	if cr.authConfig.TokenExpirationBuffer < 0 {
		return fmt.Errorf("the [token_expiration_buffer] config must be greater than or equal to 0")
	}
	return nil
}

func (cr *ConfigResolver) validateStrictUrlAuthConfigs() error {
	if cr.authConfig.LoginURL == "" {
		return fmt.Errorf("the [login_url] config must have a value when auto-configure is disabled")
	}
	if cr.authConfig.RedirectURI == "" {
		return fmt.Errorf("the [redirect_uri] config must have a value when auto-configure is disabled")
	}

	return cr.validateTenantDomainTokens()
}

func (cr *ConfigResolver) validatePartialUrlAuthConfigs() error {
	return cr.validateTenantDomainTokens()
}

func (cr *ConfigResolver) validateTenantDomainTokens() error {
	if cr.authConfig.ParseTenantFromRootDomain != "" {
		if strings.Contains(cr.authConfig.LoginURL, TenantDomainToken) {
			// Valid - token is present when required
		} else {
			return fmt.Errorf("the [login_url] must contain the \"%s\" token when using the [parse_tenant_from_root_domain] config", TenantDomainToken)
		}
		if strings.Contains(cr.authConfig.RedirectURI, TenantDomainToken) {
			// Valid - token is present when required
		} else {
			return fmt.Errorf("the [redirect_uri] must contain the \"%s\" token when using the [parse_tenant_from_root_domain] config", TenantDomainToken)
		}
	} else {
		if strings.Contains(cr.authConfig.LoginURL, TenantDomainToken) {
			return fmt.Errorf("the [login_url] cannot contain the \"%s\" token when the [parse_tenant_from_root_domain] is absent", TenantDomainToken)
		}
		if strings.Contains(cr.authConfig.RedirectURI, TenantDomainToken) {
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
	loginURL := cr.authConfig.LoginURL
	if loginURL == "" {
		loginURL = sdkConfig.LoginURL
	}

	redirectURI := cr.authConfig.RedirectURI
	if redirectURI == "" {
		redirectURI = sdkConfig.RedirectURI
	}

	parseTenantFromRootDomain := cr.authConfig.ParseTenantFromRootDomain
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
func (cr *ConfigResolver) GetClientID() string {
	return cr.authConfig.ClientID
}

func (cr *ConfigResolver) GetClientSecret() string {
	return cr.authConfig.ClientSecret
}

func (cr *ConfigResolver) GetLoginStateSecret() string {
	if cr.authConfig.LoginStateSecret != "" {
		return cr.authConfig.LoginStateSecret
	}
	return cr.authConfig.ClientSecret
}

func (cr *ConfigResolver) GetWristbandApplicationVanityDomain() string {
	return cr.authConfig.WristbandApplicationVanityDomain
}

func (cr *ConfigResolver) GetDangerouslyDisableSecureCookies() bool {
	return cr.authConfig.DangerouslyDisableSecureCookies
}

func (cr *ConfigResolver) GetScopes() []string {
	return cr.authConfig.Scopes
}

func (cr *ConfigResolver) GetAutoConfigureEnabled() bool {
	return cr.authConfig.AutoConfigureEnabled
}

func (cr *ConfigResolver) GetTokenExpirationBuffer() int {
	return cr.authConfig.TokenExpirationBuffer
}

// Dynamic configuration getters
func (cr *ConfigResolver) GetCustomApplicationLoginPageURL() (string, error) {
	// 1. Check if manually provided in authConfig
	if cr.authConfig.CustomApplicationLoginPageURL != "" {
		return cr.authConfig.CustomApplicationLoginPageURL, nil
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

func (cr *ConfigResolver) GetIsApplicationCustomDomainActive() (bool, error) {
	// 1. Check if manually provided in authConfig
	if cr.authConfig.IsApplicationCustomDomainActive != nil {
		return *cr.authConfig.IsApplicationCustomDomainActive, nil
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			return false, err
		}
		return sdkConfig.IsApplicationCustomDomainActive, nil
	}

	// 3. Default fallback
	return false, nil
}

func (cr *ConfigResolver) GetLoginURL() (string, error) {
	// 1. Check if manually provided in authConfig
	if cr.authConfig.LoginURL != "" {
		return cr.authConfig.LoginURL, nil
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

func (cr *ConfigResolver) GetParseTenantFromRootDomain() (string, error) {
	// 1. Check if manually provided in authConfig
	if cr.authConfig.ParseTenantFromRootDomain != "" {
		return cr.authConfig.ParseTenantFromRootDomain, nil
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			return "", err
		}
		return sdkConfig.LoginURLTenantDomainSuffix, nil
	}

	// 3. Default fallback
	return "", nil
}

func (cr *ConfigResolver) GetRedirectURI() (string, error) {
	// 1. Check if manually provided in authConfig
	if cr.authConfig.RedirectURI != "" {
		return cr.authConfig.RedirectURI, nil
	}

	// 2. If auto-configure is enabled, get from SDK config
	if cr.GetAutoConfigureEnabled() {
		sdkConfig, err := cr.loadSdkConfig()
		if err != nil {
			return "", err
		}
		return sdkConfig.RedirectURI, nil
	}

	// 3. This should not happen if validation is done properly
	return "", fmt.Errorf("the [redirect_uri] config must have a value")
}
