package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type (
	// Session represents the user session after successful authentication
	Session struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"-"`
		// ExpiresAt is the expiration time of the access token.
		ExpiresAt          time.Time        `json:"expires_at"`
		ExpiresIn          time.Duration    `json:"expiresIn"`
		UserInfo           UserInfoResponse `json:"user_info"`
		ReturnURL          string           `json:"-"`
		UserID             string           `json:"userID"`
		Name               string           `json:"name"`
		TenantID           string           `json:"tenantId"`
		IDPName            string           `json:"idpName"`
		TenantName         string           `json:"tenantName"`
		CustomTenantDomain string           `json:"customTenantDomain"`
	}

	// SessionManager defines the interface for session management
	SessionManager interface {
		// StoreSession stores the session after successful authentication
		StoreSession(ctx context.Context, w http.ResponseWriter, r *http.Request, session *Session) error

		// GetSession retrieves the current session
		GetSession(ctx context.Context, r *http.Request) (*Session, error)

		// ClearSession removes the current session
		ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error
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
		httpCtx := app.HTTPContext(res, req)
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")

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

// CallbackHandler creates a middleware for handling the OAuth callback
func (app WristbandApp) CallbackHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		ctx := app.HTTPContext(res, req)
		// Create session
		callbackContext, err := app.HandleCallback(ctx)
		if err != nil {
			if redirectError, ok := IsRedirectError(err); ok {
				http.Redirect(res, req, redirectError.URL, http.StatusSeeOther)
			}
			http.Error(res, "Failed to handle callback", http.StatusInternalServerError)
			return
		}

		// Store session using the session manager
		if err := app.SessionManager.StoreSession(req.Context(), res, req, callbackContext.Session()); err != nil {
			http.Error(res, "Failed to store session", http.StatusInternalServerError)
			return
		}

		// Clear login state cookie
		ctx.ClearCookie(callbackContext.LoginState.CookieName())

		// Clear any other remaining old login cookies
		app.clearAllLoginCookies(ctx)

		// Redirect to return URL or default location
		redirectURL := "/"
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
		ctx := req.Context()
		httpContext := app.HTTPContext(res, req)

		// Get session from session manager
		session, err := app.SessionManager.GetSession(ctx, req)
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
		}

		// Try to revoke refresh token
		if session.RefreshToken != "" {
			_ = app.RevokeToken(session.RefreshToken, RefreshTokenType)
		}

		// Clear session
		if err := app.SessionManager.ClearSession(req.Context(), res, req); err != nil {
			http.Error(res, "Failed to clear session", http.StatusInternalServerError)
			return
		}

		// Redirect to Wristband logout
		http.Redirect(res, req, url, http.StatusFound)
	}
}

// SessionResponse is the structure returned by the SessionHandler.
type SessionResponse struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
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
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			http.Error(res, "Unauthorized access: user not authenticated", http.StatusUnauthorized)
			return
		}

		resp := SessionResponse{
			UserID:   session.UserID,
			TenantID: session.TenantID,
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
		res.WriteHeader(http.StatusOK)
		res.Header().Set("Content-Type", "application/json")
		_, err = res.Write(respBytes)
		if err != nil {
			http.Error(res, "problem writing response", http.StatusInternalServerError)
			return
		}
	}
}
