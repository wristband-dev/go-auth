package go_auth

import (
	"fmt"
	"net/http"
)

func NewWristbandAuth(client ConfidentialClient, domains AppDomains, opts ...AppOption) WristbandAuth {
	auth := WristbandAuth{
		Client:            client,
		Domains:           domains,
		Scopes:            defaultScopes,
		tokenEndpoint:     DefaultTokenEndpoint,
		authorizeEndpoint: DefaultAuthorizeEndpoint,
		userInfoEndpoint:  DefaultUserInfoEndpoint,
		logoutEndpoint:    DefaultLogoutEndpoint,
		revokeEndpoint:    DefaultRevokeEndpoint,
		endpointRoot:      domains.WristbandDomain + DefaultApiPath,
		httpClient:        http.DefaultClient,
		tokenExpiryBuffer: DefaultTokenExpiryBuffer,
	}

	for _, opt := range opts {
		opt.apply(&auth)
	}

	auth.tokenUrl = fmt.Sprintf("https://%s", auth.endpointRoot+auth.tokenEndpoint)

	return auth
}

type WristbandAuth struct {
	// Required configuration
	Client ConfidentialClient

	// Domains provides the application domain configuration.
	Domains AppDomains

	// Scopes are the requested scopes for the auth requests.
	Scopes []string

	// Endpoint customization (optional)
	tokenEndpoint     string
	authorizeEndpoint string
	userInfoEndpoint  string
	logoutEndpoint    string
	revokeEndpoint    string
	endpointRoot      string
	logoutRedirectURI string // Optional redirect URI after logout if no redirect is resolved from the request.

	// Advanced settings
	httpClient        *http.Client
	tokenExpiryBuffer int // seconds

	cookieEncryption CookieEncryption
	tokenUrl         string
}

func (auth WristbandAuth) ResolveLogoutEndpoint(values QueryValueResolver) string {
	return auth.Domains.TenantedHost(values) + auth.logoutEndpoint
}

func (auth WristbandAuth) LogoutEndpoint(req *http.Request) string {
	return auth.Domains.RequestTenantedHost(req) + auth.logoutEndpoint
}

func (auth WristbandAuth) AuthorizeEndpoint(req *http.Request) string {
	return auth.Domains.RequestTenantedHost(req) + auth.authorizeEndpoint
}

func (auth WristbandAuth) ResolveAuthorizeEndpoint(values QueryValueResolver) string {
	return auth.Domains.TenantedHost(values) + auth.authorizeEndpoint
}

func (auth WristbandAuth) UserInfoEndpoint() string {
	return auth.endpointRoot + auth.userInfoEndpoint
}

func (auth WristbandAuth) CodeTokenRequest(code, codeVerifier, redirectURI string) TokenRequest {
	return TokenRequest{
		Client:       auth.Client,
		Scopes:       auth.Scopes,
		Endpoint:     auth.tokenEndpoint,
		GrantType:    GrantTypeCode,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
	}
}

func (auth WristbandAuth) TokenRequestConf() TokenRequestConfig {
	return TokenRequestConfig{
		Client:   auth.Client,
		Endpoint: auth.tokenUrl,
	}
}

func (auth WristbandAuth) RevokeEndpoint() string {
	return auth.endpointRoot + auth.revokeEndpoint
}

type AppOption interface {
	apply(*WristbandAuth)
}

type appOptionFunc func(*WristbandAuth)

func (f appOptionFunc) apply(c *WristbandAuth) {
	f(c)
}
