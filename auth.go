package goauth

import (
	"fmt"
	"net/http"

	"github.com/wristband-dev/go-auth/cookies"
	"github.com/wristband-dev/go-auth/rand"
)

// WristbandAuth creates a WristbandAuth instance from this AuthConfig.
func (ac *AuthConfig) WristbandAuth(opts ...AuthOption) (WristbandAuth, error) {
	resolver, err := NewConfigResolver(ac)
	if err != nil {
		return WristbandAuth{}, err
	}

	// Initialize WristbandAuth with all required fields
	auth := WristbandAuth{
		Client:           resolver.wristbandAPI,
		tokenEndpoint:    DefaultTokenEndpoint,
		userInfoEndpoint: DefaultUserInfoEndpoint,
		revokeEndpoint:   DefaultRevokeEndpoint,
		endpointRoot:     ac.WristbandApplicationVanityDomain + DefaultAPIPath,
		httpClient:       http.DefaultClient,
		configResolver:   resolver,
	}

	// Apply any provided options
	for _, opt := range opts {
		opt.apply(&auth)
	}

	// Set up cookie encryption
	if auth.cookieEncryption == nil {
		// Use LoginStateSecret if provided, otherwise use ClientSecret
		key := []byte(resolver.getLoginStateSecret())
		if len(key) < 32 {
			// Generate a random key if the secret is too short
			key = rand.GenerateRandomKey(32)
		} else if len(key) > 32 {
			// Truncate to 32 bytes if too long
			key = key[:32]
		}
		auth.cookieEncryption, err = cookies.NewCookieEncryptor(key)
		if err != nil {
			return WristbandAuth{}, err
		}
	}

	// Set the token URL
	auth.tokenURL = fmt.Sprintf("https://%s", auth.endpointRoot+auth.tokenEndpoint)

	return auth, nil
}

// WristbandAuth provides the configuration and methods for authenticating with Wristband.
type WristbandAuth struct {
	// Required configuration
	Client ConfidentialClient

	// Endpoint customization (optional)
	tokenEndpoint    string
	userInfoEndpoint string
	revokeEndpoint   string
	endpointRoot     string

	// Advanced settings
	httpClient *http.Client

	cookieEncryption CookieEncryption
	tokenURL         string

	// ConfigResolver provides dynamic configuration resolution
	configResolver *ConfigResolver

	cookieOptions CookieOptions
}

// UserInfoEndpoint returns the user info endpoint URL for fetching user details.
func (auth WristbandAuth) UserInfoEndpoint() string {
	return auth.endpointRoot + auth.userInfoEndpoint
}

// CodeTokenRequest creates a TokenRequest for exchanging an authorization code for an access token.
func (auth WristbandAuth) CodeTokenRequest(code, codeVerifier string) TokenRequest {
	return TokenRequest{
		Client:       auth.Client,
		Scopes:       auth.configResolver.GetScopes(),
		Endpoint:     auth.tokenURL,
		GrantType:    GrantTypeCode,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  auth.configResolver.GetRedirectURI(),
	}
}

// RevokeEndpoint returns the endpoint URL for revoking tokens.
func (auth WristbandAuth) RevokeEndpoint() string {
	return auth.endpointRoot + auth.revokeEndpoint
}

func (auth WristbandAuth) defaultCookieOptions() CookieOptions {
	dangerouslyDisableSecureCookies := false
	if auth.configResolver != nil {
		dangerouslyDisableSecureCookies = auth.configResolver.GetDangerouslyDisableSecureCookies()
	}
	return CookieOptions{
		Path:                            "/",
		SameSite:                        http.SameSiteLaxMode,
		MaxAge:                          3600,
		DangerouslyDisableSecureCookies: dangerouslyDisableSecureCookies,
	}
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

// WithCookieOptions sets the cookie configuration for the app.
func WithCookieOptions(cookieOptions CookieOptions) AuthOption {
	return authOptionFunc(func(c *WristbandAuth) {
		c.cookieOptions = cookieOptions
	})
}

// WithCookieEncryption allows setting a custom CookieEncryption implementation.
func WithCookieEncryption(cookieEncryption CookieEncryption) AuthOption {
	return authOptionFunc(func(c *WristbandAuth) {
		c.cookieEncryption = cookieEncryption
	})
}

type authOptionFunc func(*WristbandAuth)

func (f authOptionFunc) apply(c *WristbandAuth) {
	f(c)
}
