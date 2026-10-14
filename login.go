package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wristband-dev/go-auth/rand"
)

type (
	// LoginState represents the state during login process
	LoginState struct {
		// ReturnURL is the URL to return to after authentication is completed. In the CallbackContext returned by
		// HandleCallback, it has been validated to prevent open redirects: it is empty if it pointed to a host other
		// than the request's host or the root domain, or used a different scheme than the request.
		ReturnURL      string `json:"return_url,omitempty"`
		Nonce          string `json:"nonce,omitempty"`
		CodeVerifier   string `json:"code_verifier,omitempty"`
		CustomState    any    `json:"custom_state,omitempty"`
		StateCookieKey string `json:"-"`
		CreatedAt      int64  `json:"created_at,omitempty"`
	}

	// LoginOptions represents options for the login process
	LoginOptions struct {
		// customState data for the login request.
		customState map[string]any
		// returnURL is the URL to return to after authentication is completed.
		// If a value is provided, then it takes precedence over the return_url request query parameter.
		returnURL string

		// defaultTenantCustomDomain is an optional default tenant custom domain to use for the
		// login request in the event the tenant custom domain cannot be found in the
		// "tenant_custom_domain" request query parameter.
		defaultTenantCustomDomain string
		// defaultTenantName is an optional default tenant name to use for the login request in the
		// event the name cannot be found in either the subdomain or the "tenant_name" request
		// query parameter (depending on your subdomain configuration).
		defaultTenantName string

		authorizeRequestOpts []AuthorizeRequestOption
	}

	// LoginOpt is used to modify LoginOptions configuration.
	LoginOpt interface {
		apply(*LoginOptions)
	}
)

// WithDefaultTenantCustomDomain sets the default tenant custom domain used for logins.
func WithDefaultTenantCustomDomain(domain string) LoginOpt {
	return loginOptFn(func(o *LoginOptions) {
		o.defaultTenantCustomDomain = domain
	})
}

// WithDefaultTenantName sets the default tenant name that should be used for logins.
func WithDefaultTenantName(name string) LoginOpt {
	return loginOptFn(func(o *LoginOptions) {
		o.defaultTenantName = name
	})
}

// WithReturnURL sets the URL to return to after authentication is completed.
// If a value is provided, then it takes precedence over the return_url request query parameter.
func WithReturnURL(url string) LoginOpt {
	return loginOptFn(func(o *LoginOptions) {
		o.returnURL = url
	})
}

// WithCustomState sets the custom state for the login request.
func WithCustomState(state map[string]any) LoginOpt {
	return loginOptFn(func(o *LoginOptions) {
		o.customState = state
	})
}

// NewLoginOptions returns default login options
func NewLoginOptions(opts ...LoginOpt) *LoginOptions {
	options := &LoginOptions{}
	for _, opt := range opts {
		opt.apply(options)
	}
	return options
}

// HandleLogin initiates the login process by creating a login state and returning the authorization url.
//
// When no tenant can be resolved from the request and application-level authorization requests are enabled (the
// default), it returns the Wristband Authorize Endpoint URL on the application vanity domain, and Wristband
// handles tenant discovery within that same authorization flow. When they are disabled, it returns the
// Application-Level Login (Tenant Discovery) Page URL with the return URL in the state query parameter.
func (auth WristbandAuth) HandleLogin(httpCtx HTTPContext, options *LoginOptions) (string, error) {
	baseURL, err := auth.loginBaseURL(httpCtx, options)
	if err != nil {
		if !errors.Is(err, ErrTenantNameNotFound) {
			return "", err
		}
		if auth.configResolver.GetApplicationAuthorizationRequestsEnabled() {
			return auth.startAuthorizeRequest(httpCtx, options, auth.configResolver.GetWristbandApplicationVanityDomain())
		}
		params := url.Values{}
		params.Set("client_id", auth.Client.ClientID)
		if returnURL := options.resolveReturnURL(httpCtx); returnURL != "" {
			params.Set("state", returnURL)
		}
		if customURL, err := auth.configResolver.GetCustomApplicationLoginPageURL(); err == nil && customURL != "" {
			return customURL + "?" + params.Encode(), nil
		}
		return "https://" + auth.configResolver.GetWristbandApplicationVanityDomain() + "/login?" + params.Encode(), nil
	}

	return auth.startAuthorizeRequest(httpCtx, options, baseURL)
}

// loginStateCookieDomain returns the domain for the login state cookie. With application-level authorization
// requests and tenant subdomains, a login can start on the root domain and finish on a tenant subdomain, so the
// cookie is set on the root domain. Otherwise, it is host-only.
func (auth WristbandAuth) loginStateCookieDomain() string {
	if auth.configResolver == nil {
		return ""
	}
	if rootDomain := auth.configResolver.GetParseTenantFromRootDomain(); rootDomain != "" &&
		auth.configResolver.GetApplicationAuthorizationRequestsEnabled() {
		return "." + rootDomain
	}
	return ""
}

// startAuthorizeRequest creates the login state cookie and returns the Wristband Authorize Endpoint URL on baseURL.
func (auth WristbandAuth) startAuthorizeRequest(httpCtx HTTPContext, options *LoginOptions, baseURL string) (string, error) {
	// Create login state with nonce, PKCE code verifier, etc.
	state := CreateLoginState(httpCtx.Query(), options)

	stateValue, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to serialize login state: %v", err)
	}
	cookieName := state.CookieName()
	cookieValue, err := auth.cookieEncryption.EncryptCookieValue(cookieName, string(stateValue))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt cookie: %v", err)
	}

	// Cleanup old login state cookies - keep only the 2 most recent
	cookieDomain := auth.loginStateCookieDomain()
	auth.cleanupOldLoginCookies(httpCtx, cookieDomain)

	// Store login state in a cookie
	if err := writeCookie(httpCtx, cookieName, cookieValue, cookieDomain); err != nil {
		return "", fmt.Errorf("failed to write login state cookie: %v", err)
	}
	opts := []AuthorizeRequestOption{
		WithNonce(state.Nonce),
		WithCodeVerifier(state.CodeVerifier),
		WithScopes(auth.configResolver.Scopes...),
	}
	if options != nil && options.authorizeRequestOpts != nil {
		opts = append(options.authorizeRequestOpts, opts...)
	}
	// Create authorization request with state, nonce, and PKCE code verifier
	authReq := auth.NewAuthorizeRequest(state.StateCookieKey,
		opts...,
	)
	// Build authorization URL
	return authReq.AuthorizeURL(httpCtx, baseURL), nil
}

// ReturnURLMaxLength is the maximum length of the return URL.
const ReturnURLMaxLength = 450

func (options *LoginOptions) resolveReturnURL(req HTTPContext) string {
	// The return URL from the LoginOptions takes priority over the query param.
	returnURL := req.Query().Get("return_url")
	if options != nil && options.returnURL != "" {
		returnURL = options.returnURL
	}
	if len(returnURL) > ReturnURLMaxLength {
		return ""
	}
	return returnURL
}

func (auth WristbandAuth) loginBaseURL(req HTTPContext, options *LoginOptions) (string, error) {
	// An invalid tenant custom domain is skipped over rather than failing the login, so
	// resolution falls through to the next domain in the precedence order below.
	tenantCustomDomain, err := auth.requestValidCustomTenantName(req)
	if err != nil {
		return "", err
	}
	if tenantCustomDomain != "" {
		return tenantCustomDomain, nil
	}
	if tenantName, err := auth.RequestTenantName(req); err == nil && tenantName != "" {
		return strings.Join([]string{tenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}

	if options == nil {
		return "", ErrTenantNameNotFound
	}

	if options.defaultTenantCustomDomain != "" {
		return options.defaultTenantCustomDomain, nil
	}
	if options.defaultTenantName != "" {
		return strings.Join([]string{options.defaultTenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}
	return "", ErrTenantNameNotFound
}

// cleanupOldLoginCookies removes all but the 2 most recent login state cookies.
func (auth WristbandAuth) cleanupOldLoginCookies(httpCtx HTTPContext, cookieDomain string) {
	type cookieWithTimestamp struct {
		name      string
		timestamp int64
	}

	// Get all cookie names from the request
	allCookieNames := httpCtx.CookieRequest().Cookies()
	var loginCookies []cookieWithTimestamp

	// Filter and parse login state cookies
	for _, cookieName := range allCookieNames {
		if !strings.HasPrefix(cookieName, LoginStateCookiePrefix) {
			continue
		}
		_, timestamp, err := parseLoginStateCookieName(cookieName)
		if err != nil {
			// If we can't parse it, skip it (may be an old format or invalid)
			continue
		}
		loginCookies = append(loginCookies, cookieWithTimestamp{
			name:      cookieName,
			timestamp: timestamp,
		})
	}

	// If we have 2 or fewer cookies, no cleanup needed
	if len(loginCookies) <= 2 {
		return
	}

	// Sort by timestamp (most recent first)
	sort.Slice(loginCookies, func(i, j int) bool {
		return loginCookies[i].timestamp > loginCookies[j].timestamp
	})

	// Clear all but the 2 most recent
	for i := 2; i < len(loginCookies); i++ {
		clearCookie(httpCtx, loginCookies[i].name, cookieDomain)
	}
}

// CreateLoginState creates a new login state with PKCE and nonce
func CreateLoginState(queryValues QueryValueResolver, options *LoginOptions) LoginState {
	returnURL := queryValues.Get("return_url")
	var customState any
	if options != nil {
		if options.returnURL != "" {
			returnURL = options.returnURL
		}
		customState = options.customState
	}
	// Generate nonce and code verifier
	return LoginState{
		// Get return URL from query parameters
		ReturnURL:      returnURL,
		Nonce:          rand.GenerateRandomString(32),
		CodeVerifier:   rand.GenerateRandomString(32),
		StateCookieKey: rand.GenerateRandomCookieName(16),
		CustomState:    customState,
		CreatedAt:      time.Now().UnixMilli(),
	}
}

// CookieName returns the name of the cookie used to store the login state.
func (state LoginState) CookieName() string {
	return loginStateCookieName(state.StateCookieKey, state.CreatedAt)
}

// CallbackContext contains contextual information retrieved in the callback endpoint.
type CallbackContext struct {
	TokenResponse      TokenResponse
	LoginState         LoginState
	UserInfo           UserInfoResponse
	TenantName         string
	TenantCustomDomain string
}

// ErrorNoLoginState is returned when no login state is found.
var ErrorNoLoginState = errors.New("no login state found")

// HandleCallback processes the OAuth callback, exchanges the authorization code for tokens.
func (auth WristbandAuth) HandleCallback(httpCtx HTTPContext) (*CallbackContext, error) {
	if err := RequestError(httpCtx.Query()); err != nil {
		return nil, err
	}
	inputs, err := auth.getCallbackInputs(httpCtx)
	if err != nil {
		return nil, err
	}
	if inputs.Code == "" {
		return nil, InvalidParameterError("code")
	}
	rootDomain := auth.configResolver.GetParseTenantFromRootDomain()
	if inputs.TenantName == "" {
		if rootDomain != "" {
			return nil, NewWristbandError("missing_tenant_subdomain", "callback request URL is missing a tenant subdomain")
		}
		return nil, NewWristbandError("missing_tenant_name", "callback request is missing the [tenant_name] query parameter from Wristband")
	}
	loginURL, err := auth.configResolver.GetLoginURL()
	if err != nil {
		return nil, err
	}
	queryVals := url.Values{}
	if rootDomain != "" {
		loginURL = strings.ReplaceAll(loginURL, TenantNameToken, inputs.TenantName)
	} else {
		queryVals.Set("tenant_name", inputs.TenantName)
	}
	if inputs.TenantCustomDomain != "" {
		queryVals.Set("tenant_custom_domain", inputs.TenantCustomDomain)
	}
	tenantURL := loginURL
	if len(queryVals) > 0 {
		tenantURL += "?" + queryVals.Encode()
	}

	// A login state cookie that is missing, can't be decrypted (tampered or encrypted with a different secret),
	// or is older than its lifetime can't be trusted, so restart the login.
	loginState, err := GetLoginStateCookie(auth.cookieEncryption, httpCtx)
	if err != nil {
		return nil, NewRedirectError("failed to retrieve login state", tenantURL)
	}
	if isLoginStateExpired(loginState, time.Now()) {
		return nil, NewRedirectError("login state expired", tenantURL)
	}

	// Prevent open redirects by validating the return URL against allowed hosts.
	scheme := "https"
	if schemeResolver, ok := httpCtx.(RequestScheme); ok {
		scheme = schemeResolver.Scheme()
	}
	loginState.ReturnURL = validateReturnURL(
		loginState.ReturnURL,
		scheme,
		httpCtx.Host(),
		inputs.TenantName,
		auth.configResolver.GetApplicationAuthorizationRequestsEnabled(),
		rootDomain,
	)

	tokenReq := auth.CodeTokenRequest(inputs.Code, loginState.CodeVerifier)

	// Exchange code for tokens
	tokenResponse, err := tokenReq.Do(auth.httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %v", err)
	}

	// Calculate token expiration buffer
	bufferSec := auth.configResolver.GetTokenExpirationBuffer()
	tokenResponse.ExpiresIn -= bufferSec
	if tokenResponse.ExpiresIn < 0 {
		tokenResponse.ExpiresIn = 0
	}

	// Get user info with access token
	userInfo, err := auth.getUserInfo(tokenResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %v", err)
	}

	// Create callback context with token response, login state, and user info
	return &CallbackContext{
		TokenResponse:      tokenResponse,
		LoginState:         loginState,
		UserInfo:           userInfo,
		TenantName:         inputs.TenantName,
		TenantCustomDomain: inputs.TenantCustomDomain,
	}, nil
}

// Session returns a *Session object from the callback context.
func (ctx CallbackContext) Session() *Session {
	expiresIn := time.Second * time.Duration(ctx.TokenResponse.ExpiresIn)
	return &Session{
		AccessToken:          ctx.TokenResponse.AccessToken,
		ExpiresAt:            time.Now().UTC().Add(expiresIn).UnixMilli(),
		IdentityProviderName: ctx.UserInfo.IdpName,
		RefreshToken:         ctx.TokenResponse.RefreshToken,
		TenantCustomDomain:   ctx.TenantCustomDomain,
		TenantId:             ctx.UserInfo.TenantId,
		TenantName:           ctx.TenantName,
		UserId:               ctx.UserInfo.Sub,
		UserInfo:             ctx.UserInfo,
	}
}

type loginOptFn func(*LoginOptions)

func (fn loginOptFn) apply(options *LoginOptions) {
	fn(options)
}
