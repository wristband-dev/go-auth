package goauth

import (
	"encoding/json"
	"net/http"
	"strings"
)

type (
	// Session represents the user session after successful authentication
	Session struct {
		AccessToken          string           `json:"accessToken"`
		RefreshToken         string           `json:"refreshToken"`
		ExpiresAt            int64            `json:"expiresAt"`
		IdentityProviderName string           `json:"identityProviderName"`
		UserInfo             UserInfoResponse `json:"userInfo"`
		UserId               string           `json:"userId"`
		TenantId             string           `json:"tenantId"`
		TenantName           string           `json:"tenantName"`
		TenantCustomDomain   string           `json:"tenantCustomDomain"`
		// CustomData can be used for any additional session data.
		CustomData map[string]any `json:"customData"`
	}

	// SessionManager defines the interface for session management
	SessionManager interface {
		// StoreSession stores the session after successful authentication
		StoreSession(w http.ResponseWriter, r *http.Request, session *Session) error

		// GetSession retrieves the current session
		GetSession(r *http.Request) (*Session, error)

		// ClearSession removes the current session
		ClearSession(w http.ResponseWriter, r *http.Request) error
	}
)

// NewApp returns a new WristbandApp to use the default http.Handler endpoint implementations.
func (auth WristbandAuth) NewApp(sessionMgr SessionManager, opts ...AppOption) WristbandApp {
	app := WristbandApp{
		WristbandAuth:  auth,
		SessionManager: sessionMgr,
	}
	for _, opt := range opts {
		opt.apply(&app)
	}

	return app
}

// AppOption is an interface for options that can be applied to modify the WristbandApp configuration. Unused for now.
type AppOption interface {
	apply(*WristbandApp)
}

type appOptionFunc func(*WristbandApp)

func (f appOptionFunc) apply(c *WristbandApp) {
	f(c)
}

// WristbandApp extends the WristbandAuth by providing http.Handler implementations for the necessary Wristband Endpoints.
// It requires a SessionManager.
type WristbandApp struct {
	WristbandAuth
	// SessionManager is used for reading and writing sessions.
	SessionManager SessionManager
}

// HTTPContext creates a new HTTPContext for the standard library request and response.
func (app WristbandApp) HTTPContext(res http.ResponseWriter, req *http.Request) HTTPContext {
	return &StandardHTTP{
		req:              req,
		res:              res,
		cookieOpts:       app.cookieOptions,
		cookieEncryption: app.cookieEncryption,
	}
}

// LoginHandler creates a middleware for initiating a login request
func (app WristbandApp) LoginHandler(opts ...LoginOpt) http.HandlerFunc {
	options := NewLoginOptions(opts...)

	return func(res http.ResponseWriter, req *http.Request) {
		// Avoid caching.
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")
		httpCtx := app.HTTPContext(res, req)

		// Build authorization URL
		authURL, err := app.HandleLogin(httpCtx, options)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		// Redirect to Wristband authorize endpoint
		http.Redirect(res, req, authURL, http.StatusFound)
	}
}

type (
	// callbackHandlerConfig are the optional configuration for the CallbackHandler.
	callbackHandlerConfig struct {
		// redirectURL is the static url to redirect to after completing the callback.
		redirectURL string
	}

	CallbackOption interface {
		apply(options *callbackHandlerConfig)
	}
	callbackOptionFunc func(*callbackHandlerConfig)
)

func (f callbackOptionFunc) apply(options *callbackHandlerConfig) {
	f(options)
}

// WithCallbackRedirectURL sets the url that the WristbandApp.CallbackHandler should redirect to upon success.
func WithCallbackRedirectURL(url string) CallbackOption {
	return callbackOptionFunc(func(options *callbackHandlerConfig) {
		options.redirectURL = url
	})
}

// CallbackHandler creates a middleware for handling the OAuth callback
func (app WristbandApp) CallbackHandler(opts ...CallbackOption) http.HandlerFunc {
	cfg := callbackHandlerConfig{}
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	return func(res http.ResponseWriter, req *http.Request) {
		// Avoid caching.
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")
		ctx := app.HTTPContext(res, req)
		// Create session
		callbackContext, err := app.HandleCallback(ctx)
		if err != nil {
			if redirectError, ok := IsRedirectError(err); ok {
				http.Redirect(res, req, redirectError.URL, http.StatusSeeOther)
				return
			}
			http.Error(res, "Failed to handle callback", http.StatusInternalServerError)
			return
		}

		// Store session using the session manager
		if err := app.SessionManager.StoreSession(res, req, callbackContext.Session()); err != nil {
			http.Error(res, "Failed to store session", http.StatusInternalServerError)
			return
		}

		// Clear login state cookie
		ctx.ClearCookie(callbackContext.LoginState.CookieName())

		// Clear any other remaining old login cookies
		app.clearAllLoginCookies(ctx)

		// Redirect to return URL or default location
		redirectURL := "/"
		if cfg.redirectURL != "" {
			redirectURL = cfg.redirectURL
		}
		if url := callbackContext.LoginState.ReturnURL; url != "" {
			redirectURL = url
		}

		http.Redirect(res, req, redirectURL, http.StatusFound)
	}
}

// clearAllLoginCookies removes all login state cookies from the request.
func (app WristbandApp) clearAllLoginCookies(ctx HTTPContext) {
	allCookieNames := ctx.CookieRequest().Cookies()
	for _, cookieName := range allCookieNames {
		if strings.HasPrefix(cookieName, LoginStateCookiePrefix) {
			ctx.ClearCookie(cookieName)
		}
	}
}

// LogoutHandler creates a middleware for logging out users
func (app WristbandApp) LogoutHandler(opts ...LogoutOption) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		// Avoid caching.
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")
		httpContext := app.HTTPContext(res, req)

		// Get session from session manager
		session, err := app.SessionManager.GetSession(req)
		if err != nil {
			if url, err := app.LogoutURL(httpContext, NewLogoutConfig()); err == nil {
				// If no session, just redirect to Wristband logout
				http.Redirect(res, req, url, http.StatusFound)
				return
			}
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		logoutCfg := NewLogoutConfig(append([]LogoutOption{WithSession(*session)}, opts...)...)

		url, err := app.LogoutURL(httpContext, logoutCfg)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		// Try to revoke refresh token
		if session.RefreshToken != "" {
			_ = app.RevokeToken(session.RefreshToken, RefreshTokenType)
		}

		// Clear session
		if err := app.SessionManager.ClearSession(res, req); err != nil {
			http.Error(res, "Failed to clear session", http.StatusInternalServerError)
			return
		}

		// Redirect to Wristband logout
		http.Redirect(res, req, url, http.StatusFound)
	}
}

// SessionEndpointResponse is the structure returned by the SessionHandler.
type SessionEndpointResponse struct {
	UserId   string `json:"userId"`
	TenantId string `json:"tenantId"`
	Metadata any    `json:"metadata"`
}

// SessionHandlerConfig is the configuration for the SessionHandler.
type SessionHandlerConfig struct {
	sessionMetadataExtractor func(Session) any
}

// SessionHandlerOption is an interface for options that can be applied to modify the SessionHandler configuration.
type SessionHandlerOption interface {
	apply(*SessionHandlerConfig)
}

// sessionHandlerOptionFunc is a function that sets configuration options for the SessionHandler.
type sessionHandlerOptionFunc func(*SessionHandlerConfig)

func (fn sessionHandlerOptionFunc) apply(c *SessionHandlerConfig) {
	fn(c)
}

// WithSessionMetadataExtractor sets the function that is used to set the metadata returned by the Session handler.
func WithSessionMetadataExtractor(metadataFn func(Session) any) SessionHandlerOption {
	return sessionHandlerOptionFunc(func(c *SessionHandlerConfig) {
		c.sessionMetadataExtractor = metadataFn
	})
}

// SessionHandler is an http.HandlerFunc that retrieves the current user session.
func (app WristbandApp) SessionHandler(opts ...SessionHandlerOption) http.HandlerFunc {
	cfg := SessionHandlerConfig{}
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	return func(res http.ResponseWriter, req *http.Request) {
		session, err := app.SessionManager.GetSession(req)
		if err != nil {
			http.Error(res, "Unauthorized access: user not authenticated", http.StatusUnauthorized)
			return
		}

		resp := SessionEndpointResponse{
			UserId:   session.UserId,
			TenantId: session.TenantId,
		}
		if cfg.sessionMetadataExtractor != nil {
			resp.Metadata = cfg.sessionMetadataExtractor(*session)
		} else {
			resp.Metadata = session.UserInfo
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			http.Error(res, "problem serializing session data", http.StatusInternalServerError)
			return
		}
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		_, err = res.Write(respBytes)
		if err != nil {
			http.Error(res, "problem writing response", http.StatusInternalServerError)
			return
		}
	}
}

// TokenEndpointResponse is the structure returned by the TokenHandler.
type TokenEndpointResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// TokenHandler is an http.HandlerFunc that returns the access token for the current session.
func (app WristbandApp) TokenHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		session, err := app.SessionManager.GetSession(req)
		if err != nil {
			http.Error(res, "Unauthorized access: user not authenticated", http.StatusUnauthorized)
			return
		}

		resp := TokenEndpointResponse{
			AccessToken: session.AccessToken,
			ExpiresAt:   session.ExpiresAt,
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			http.Error(res, "problem serializing token data", http.StatusInternalServerError)
			return
		}
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		_, err = res.Write(respBytes)
		if err != nil {
			http.Error(res, "problem writing response", http.StatusInternalServerError)
			return
		}
	}
}
