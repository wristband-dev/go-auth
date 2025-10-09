package goauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/wristband-dev/go-auth/cookies"
	"github.com/wristband-dev/go-auth/rand"
)

// WristbandAuthConfig holds the configuration for Wristband authentication that is required.
type WristbandAuthConfig struct {
	// Client is the confidential client used for authentication.
	Client ConfidentialClient
	// Domains provides the application domain configuration.
	Domains AppDomains
	// SecretKey is the key used for encrypting cookies.
	// If empty, a random key will be generated. If set, it must be 32 bytes long.
	SecretKey []byte
	// AuthConfig provides the authentication configuration for the new config resolver pattern.
	// This is an alternative to the individual fields above and provides more flexibility.
	AuthConfig *AuthConfig
}

// NewWristbandAuth returns a new WristbandAuth instance configured with the provided settings.
func NewWristbandAuth(cfg WristbandAuthConfig, opts ...AuthOption) (WristbandAuth, error) {
	if err := cfg.Domains.Validate(); err != nil {
		return WristbandAuth{}, fmt.Errorf("invalid domains configuration: %w", err)
	}
	if cfg.Domains.DefaultDomains != nil {
		separator := "-"
		if cfg.Domains.IsApplicationCustomDomainActive {
			separator = "."
		}
		cfg.Domains.DefaultDomains.separator = separator
	}

	if len(cfg.SecretKey) != 0 && len(cfg.SecretKey) != 32 {
		return WristbandAuth{}, errors.New("secret key is must be exactly 32 bytes")
	}

	// If AuthConfig is provided, create a ConfigResolver
	var configResolver *ConfigResolver
	if cfg.AuthConfig != nil {
		var err error
		configResolver, err = NewConfigResolver(cfg.AuthConfig)
		if err != nil {
			return WristbandAuth{}, fmt.Errorf("failed to create config resolver: %w", err)
		}
	}

	auth := WristbandAuth{
		Client:            cfg.Client,
		Domains:           cfg.Domains,
		Scopes:            defaultScopes,
		tokenEndpoint:     DefaultTokenEndpoint,
		authorizeEndpoint: DefaultAuthorizeEndpoint,
		userInfoEndpoint:  DefaultUserInfoEndpoint,
		logoutEndpoint:    DefaultLogoutEndpoint,
		revokeEndpoint:    DefaultRevokeEndpoint,
		endpointRoot:      cfg.Domains.WristbandDomain + DefaultAPIPath,
		httpClient:        http.DefaultClient,
		tokenExpiryBuffer: DefaultTokenExpiryBuffer,
		logoutRedirectURI: "/",
		configResolver:    configResolver,
	}

	for _, opt := range opts {
		opt.apply(&auth)
	}

	if auth.cookieEncryption == nil {
		key := cfg.SecretKey
		if len(key) == 0 {
			key = rand.GenerateRandomKey(32)
		}
		auth.cookieEncryption = cookies.NewCookieEncryptor(key)
	}

	auth.tokenURL = fmt.Sprintf("https://%s", auth.endpointRoot+auth.tokenEndpoint)

	return auth, nil
}

// WristbandAuth provides the configuration and methods for authenticating with Wristband.
type WristbandAuth struct {
	// Required configuration
	Client ConfidentialClient

	// Domains provides the application domain configuration.
	Domains AppDomains

	// Scopes are the requested scopes for the auth requests.
	Scopes []string

	// Endpoint customization (optional)
	tokenEndpoint        string
	authorizeEndpoint    string
	userInfoEndpoint     string
	logoutEndpoint       string
	revokeEndpoint       string
	endpointRoot         string
	logoutRedirectURI    string // Optional redirect URI after logout if no redirect is resolved from the request.
	logoutStateParameter string

	// Advanced settings
	httpClient        *http.Client
	tokenExpiryBuffer int // seconds

	cookieEncryption CookieEncryption
	tokenURL         string

	// ConfigResolver provides dynamic configuration resolution
	configResolver *ConfigResolver
}

// ResolveLogoutEndpoint returns the logout endpoint URL for a given set of query values.
func (auth WristbandAuth) ResolveLogoutEndpoint(req HTTPRequest) string {
	return auth.Domains.TenantedHost(req) + auth.logoutEndpoint
}

// UserInfoEndpoint returns the user info endpoint URL for fetching user details.
func (auth WristbandAuth) UserInfoEndpoint() string {
	return auth.endpointRoot + auth.userInfoEndpoint
}

// CodeTokenRequest creates a TokenRequest for exchanging an authorization code for an access token.
func (auth WristbandAuth) CodeTokenRequest(code, codeVerifier, redirectURI string) TokenRequest {
	return TokenRequest{
		Client:       auth.Client,
		Scopes:       auth.Scopes,
		Endpoint:     auth.tokenURL,
		GrantType:    GrantTypeCode,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
	}
}

// TokenRequestConf returns the configuration for building token requests.
func (auth WristbandAuth) TokenRequestConf() TokenRequestConfig {
	return TokenRequestConfig{
		Client:   auth.Client,
		Endpoint: auth.tokenURL,
	}
}

// RevokeEndpoint returns the endpoint URL for revoking tokens.
func (auth WristbandAuth) RevokeEndpoint() string {
	return auth.endpointRoot + auth.revokeEndpoint
}

// GetConfigResolver returns the ConfigResolver if available
func (auth WristbandAuth) GetConfigResolver() *ConfigResolver {
	return auth.configResolver
}

// GetClientID returns the client ID from the ConfigResolver if available, otherwise from the Client
func (auth WristbandAuth) GetClientID() string {
	if auth.configResolver != nil {
		return auth.configResolver.GetClientID()
	}
	return auth.Client.ClientID
}

// GetClientSecret returns the client secret from the ConfigResolver if available, otherwise from the Client
func (auth WristbandAuth) GetClientSecret() string {
	if auth.configResolver != nil {
		return auth.configResolver.GetClientSecret()
	}
	return auth.Client.ClientSecret
}

// GetScopes returns the scopes from the ConfigResolver if available, otherwise from the auth instance
func (auth WristbandAuth) GetScopes() []string {
	if auth.configResolver != nil {
		return auth.configResolver.GetScopes()
	}
	return auth.Scopes
}

// GetTokenExpiryBuffer returns the token expiry buffer from the ConfigResolver if available, otherwise from the auth instance
func (auth WristbandAuth) GetTokenExpiryBuffer() int {
	if auth.configResolver != nil {
		return auth.configResolver.GetTokenExpirationBuffer()
	}
	return auth.tokenExpiryBuffer
}

// AuthOption is an interface for options that can be applied to modify the WristbandAuth configuration.
type AuthOption interface {
	apply(*WristbandAuth)
}

// WithHTTPClient allows setting a custom HTTP client for the remote requests.
func WithHTTPClient(client *http.Client) AuthOption {
	return authOptionFunc(func(c *WristbandAuth) {
		c.httpClient = client
	})
}

// WithLogoutRedirectURL allows setting the url that users will be redirected to when logging out.
func WithLogoutRedirectURL(url string) AuthOption {
	return authOptionFunc(func(c *WristbandAuth) {
		c.logoutRedirectURI = url
	})
}

// WithCookieEncryption allows setting a custom CookieEncryption implementation.
func WithCookieEncryption(cookieEncryption CookieEncryption) AuthOption {
	return authOptionFunc(func(c *WristbandAuth) {
		c.cookieEncryption = cookieEncryption
	})
}

// WithParseTenantFromRootDomain indicates that the tenant should be derived from the incoming request's host.
func WithParseTenantFromRootDomain() AuthOption {
	return authOptionFunc(func(c *WristbandAuth) {
		c.Domains.ParseTenantFromRootDomain = true
	})
}

type authOptionFunc func(*WristbandAuth)

func (f authOptionFunc) apply(c *WristbandAuth) {
	f(c)
}
