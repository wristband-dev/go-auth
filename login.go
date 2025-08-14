package goauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/wristband-dev/go-auth/rand"
)

// LoginState represents the state during login process
type LoginState struct {
	ReturnURL      string `json:"return_url,omitempty"`
	Nonce          string `json:"nonce,omitempty"` // TODO Propagated to the ID_Token JWT as a Claim if verifying is desired.
	CodeVerifier   string `json:"code_verifier,omitempty"`
	CustomState    any    `json:"custom_state,omitempty"`
	StateCookieKey string `json:"-"`
}

// LoginOptions represents options for the login process
type LoginOptions struct {
	Scopes []string
	// CustomState data for the login request.
	CustomState map[string]any
}

// DefaultLoginOptions returns default login options
func DefaultLoginOptions() *LoginOptions {
	return &LoginOptions{
		Scopes: []string{"openid", "offline_access", "email"},
	}
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

	// Store login state in a cookie
	if err := httpCtx.WriteCookie(cookieName, cookieValue); err != nil {
		return "", fmt.Errorf("failed to write login state cookie: %v", err)
	}
	authReq := auth.NewAuthorizeRequest(callbackURL, state.StateCookieKey,
		WithNonce(state.Nonce),
		WithCodeVerifier(state.CodeVerifier),
	)
	// Build authorization URL
	return authReq.AuthorizeURL(httpCtx.Query()), nil
}

// CreateLoginState creates a new login state with PKCE and nonce
func CreateLoginState(queryValues QueryValueResolver, options *LoginOptions) LoginState {
	// Generate nonce and code verifier
	return LoginState{
		// Get return URL from query parameters
		ReturnURL:      queryValues.Get("return_url"),
		Nonce:          rand.GenerateRandomString(32),
		CodeVerifier:   rand.GenerateRandomString(32),
		StateCookieKey: rand.GenerateRandomCookieName(16),
		CustomState:    options.CustomState,
	}
}

// CookieName returns the name of the cookie used to store the login state.
func (state LoginState) CookieName() string {
	return loginStateCookieName(state.StateCookieKey)
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
	loginState, err := GetLoginStateCookie(auth.cookieEncryption, queryValues, ctx.CookieRequest())
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
		AccessToken:    ctx.TokenResponse.AccessToken,
		RefreshToken:   ctx.TokenResponse.RefreshToken,
		IDToken:        ctx.TokenResponse.IDToken,
		AccessTokenExp: expiresAt,
		ExpiresIn:      expiresIn,
		UserInfo:       ctx.UserInfo,
		ReturnURL:      ctx.LoginState.ReturnURL,
		UserId:         ctx.UserInfo.Sub,
		Name:           ctx.UserInfo.Name,
		TenantID:       ctx.UserInfo.TenantID,
	}
}
