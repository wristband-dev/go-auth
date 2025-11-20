package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wristband-dev/go-auth/rand"
)

// LoginState represents the state during login process
type LoginState struct {
	ReturnURL      string `json:"return_url,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	CodeVerifier   string `json:"code_verifier,omitempty"`
	CustomState    any    `json:"custom_state,omitempty"`
	StateCookieKey string `json:"-"`
	CreatedAt      int64  `json:"created_at,omitempty"`
}

// LoginOptions represents options for the login process
type LoginOptions struct {
	// CustomState data for the login request.
	CustomState map[string]any
	// ReturnURL is the URL to return to after authentication is completed.
	// If a value is provided, then it takes precedence over the return_url request query parameter.
	ReturnURL string

	// DefaultTenantCustomDomain is an optional default tenant custom domain to use for the
	// login request in the event the tenant custom domain cannot be found in the
	// "tenant_custom_domain" request query parameter.
	DefaultTenantCustomDomain string
	// DefaultTenantName is an optional default tenant custom domain to use for the login request in the
	// event the name cannot be found in either the subdomain or the "tenant_domain" request
	// query parameter (depending on your subdomain configuration).
	DefaultTenantName string

	AuthorizeRequestOpts []AuthorizeRequestOption
}

// WithDefaultTenantCustomDomain sets the default tenant custom domain used for logins.
func WithDefaultTenantCustomDomain(domain string) func(*LoginOptions) {
	return func(o *LoginOptions) {
		o.DefaultTenantCustomDomain = domain
	}
}

// WithDefaultTenantName sets the default tenant name that should be used for logins.
func WithDefaultTenantName(name string) func(*LoginOptions) {
	return func(o *LoginOptions) {
		o.DefaultTenantName = name
	}
}

// DefaultLoginOptions returns default login options
func DefaultLoginOptions() *LoginOptions {
	return &LoginOptions{}
}

// HandleLogin initiates the login process by creating a login state and returning the authorization url.
func (auth WristbandAuth) HandleLogin(httpCtx HTTPContext, options *LoginOptions) (string, error) {
	baseURL, err := auth.loginBaseURL(httpCtx, options)
	if err != nil {
		if errors.Is(err, ErrTenantNameNotFound) {
			params := url.Values{}
			params.Set("client_id", auth.Client.ClientID)
			if returnURL := options.returnURL(httpCtx); returnURL != "" {
				params.Set("state", strconv.Quote(returnURL))
			}
			if customURL, err := auth.configResolver.GetCustomApplicationLoginPageURL(); err == nil && customURL != "" {
				return customURL + "?" + params.Encode(), nil
			}
			return "https://" + auth.configResolver.GetWristbandApplicationVanityDomain() + "/login?" + params.Encode(), nil
		}
		return "", err
	}

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
	auth.cleanupOldLoginCookies(httpCtx)

	// Store login state in a cookie
	if err := httpCtx.WriteCookie(cookieName, cookieValue); err != nil {
		return "", fmt.Errorf("failed to write login state cookie: %v", err)
	}
	opts := []AuthorizeRequestOption{
		WithNonce(state.Nonce),
		WithCodeVerifier(state.CodeVerifier),
		WithScopes(auth.configResolver.Scopes...),
	}
	if options != nil && options.AuthorizeRequestOpts != nil {
		opts = append(options.AuthorizeRequestOpts, opts...)
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

func (options *LoginOptions) returnURL(req HTTPContext) string {
	returnURL := req.Query().Get("return_url")
	if returnURL == "" && options != nil && options.ReturnURL != "" {
		returnURL = options.ReturnURL
	}
	if len(returnURL) > ReturnURLMaxLength {
		return ""
	}
	return returnURL
}

func (auth WristbandAuth) loginBaseURL(req HTTPContext, options *LoginOptions) (string, error) {
	if customTenantDomain, ok := auth.RequestCustomTenantName(req); ok {
		return customTenantDomain, nil
	}
	if tenantName, err := auth.RequestTenantName(req); err == nil && tenantName != "" {
		return strings.Join([]string{tenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}

	if options == nil {
		return "", ErrTenantNameNotFound
	}

	if options.DefaultTenantCustomDomain != "" {
		return options.DefaultTenantCustomDomain, nil
	}
	if options.DefaultTenantName != "" {
		return strings.Join([]string{options.DefaultTenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}
	return "", ErrTenantNameNotFound
}

// cleanupOldLoginCookies removes all but the 2 most recent login state cookies.
func (auth WristbandAuth) cleanupOldLoginCookies(httpCtx HTTPContext) {
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
		httpCtx.ClearCookie(loginCookies[i].name)
	}
}

// CreateLoginState creates a new login state with PKCE and nonce
func CreateLoginState(queryValues QueryValueResolver, options *LoginOptions) LoginState {
	returnURL := queryValues.Get("return_url")
	var customState any
	if options != nil {
		if options.ReturnURL != "" {
			returnURL = options.ReturnURL
		}
		customState = options.CustomState
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
	CustomTenantDomain string
}

// ErrorNoLoginState is returned when no login state is found.
var ErrorNoLoginState = errors.New("no login state found")

// HandleCallback processes the OAuth callback, exchanges the authorization code for tokens.
func (auth WristbandAuth) HandleCallback(httpCtx HTTPContext, callbackURL string) (*CallbackContext, error) {
	if err := RequestError(httpCtx.Query()); err != nil {
		return nil, err
	}
	inputs := auth.getCallbackInputs(httpCtx)
	if inputs.Code == "" {
		return nil, InvalidParameterError("code")
	}
	if inputs.TenantName == "" {
		if auth.configResolver.GetParseTenantFromRootDomain() != "callback request URL is missing a tenant subdomain" {
			return nil, NewWristbandError("missing_tenant_subdomain", "")
		}
		return nil, NewWristbandError("missing_tenant_domain", "callback request is missing the [tenant_domain] query parameter from Wristband")
	}
	loginURL, err := auth.configResolver.GetLoginURL()
	if err != nil {
		return nil, err
	}
	queryVals := url.Values{}
	if auth.configResolver.GetParseTenantFromRootDomain() != "" {
		loginURL = strings.ReplaceAll(loginURL, TenantDomainToken, inputs.TenantName)
	} else {
		queryVals.Set("tenant_domain", inputs.TenantName)
	}
	if inputs.TenantCustomDomain != "" {
		queryVals.Set("tenant_custom_domain", inputs.TenantCustomDomain)
	}
	tenantURL := loginURL + "?" + queryVals.Encode()

	loginState, err := GetLoginStateCookie(auth.cookieEncryption, httpCtx)
	if err != nil {
		// If
		return nil, NewRedirectError("failed to retrieve login state", tenantURL)
	}

	tokenReq := auth.CodeTokenRequest(inputs.Code, loginState.CodeVerifier, callbackURL)

	// Exchange code for tokens
	tokenResponse, err := tokenReq.Do(auth.httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %v", err)
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
		CustomTenantDomain: inputs.TenantCustomDomain,
	}, nil
}

// Session returns a *Session object from the callback context.
func (ctx CallbackContext) Session() *Session {
	expiresIn := time.Second * time.Duration(ctx.TokenResponse.ExpiresIn)
	expiresAt := time.Now().Add(expiresIn)
	return &Session{
		AccessToken:        ctx.TokenResponse.AccessToken,
		RefreshToken:       ctx.TokenResponse.RefreshToken,
		IDToken:            ctx.TokenResponse.IDToken,
		ExpiresAt:          expiresAt,
		ExpiresIn:          expiresIn,
		UserInfo:           ctx.UserInfo,
		ReturnURL:          ctx.LoginState.ReturnURL,
		UserID:             ctx.UserInfo.Sub,
		Name:               ctx.UserInfo.Name,
		TenantID:           ctx.UserInfo.TenantID,
		CustomTenantDomain: ctx.CustomTenantDomain,
		TenantName:         ctx.TenantName,
	}
}
