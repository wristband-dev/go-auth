package goauth

import (
	"encoding/json"
	"fmt"
	"sort"
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

	AuthorizeRequestOpts []AuthorizeRequestOption
}

// DefaultLoginOptions returns default login options
func DefaultLoginOptions() *LoginOptions {
	return &LoginOptions{}
}

// HandleLogin initiates the login process by creating a login state and returning the authorization url.
func (auth WristbandAuth) HandleLogin(httpCtx HTTPContext, callbackURL string, options *LoginOptions) (string, error) {
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
	}
	if options != nil && options.AuthorizeRequestOpts != nil {
		opts = append(options.AuthorizeRequestOpts, opts...)
	}
	// Create authorization request with state, nonce, and PKCE code verifier
	authReq := auth.NewAuthorizeRequest(callbackURL, state.StateCookieKey,
		opts...,
	)
	// Build authorization URL
	return authReq.AuthorizeURL(httpCtx), nil
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
	TokenResponse TokenResponse
	LoginState    LoginState
	UserInfo      UserInfoResponse
}

// HandleCallback processes the OAuth callback, exchanges the authorization code for tokens.
func (auth WristbandAuth) HandleCallback(ctx HTTPContext, callbackURL string) (*CallbackContext, error) {
	queryValues := ctx.Query()
	if err := RequestError(queryValues); err != nil {
		return nil, err
	}
	inputs := getCallbackInputs(queryValues)
	if inputs.Code == "" {
		return nil, InvalidParameterError("code")
	}
	loginState, err := GetLoginStateCookie(auth.cookieEncryption, ctx)
	if err != nil {
		return nil, err
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
		TokenResponse: tokenResponse,
		LoginState:    loginState,
		UserInfo:      userInfo,
	}, nil
}

// Session returns a *Session object from the callback context.
func (ctx CallbackContext) Session() *Session {
	expiresIn := time.Second * time.Duration(ctx.TokenResponse.ExpiresIn)
	expiresAt := time.Now().Add(expiresIn)
	return &Session{
		AccessToken:  ctx.TokenResponse.AccessToken,
		RefreshToken: ctx.TokenResponse.RefreshToken,
		IDToken:      ctx.TokenResponse.IDToken,
		ExpiresAt:    expiresAt,
		ExpiresIn:    expiresIn,
		UserInfo:     ctx.UserInfo,
		ReturnURL:    ctx.LoginState.ReturnURL,
		UserID:       ctx.UserInfo.Sub,
		Name:         ctx.UserInfo.Name,
		TenantID:     ctx.UserInfo.TenantID,
	}
}
