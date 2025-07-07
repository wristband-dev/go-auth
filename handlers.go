package go_auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type (
	// Session represents the user session after successful authentication
	Session struct {
		AccessToken    string           `json:"access_token"`
		RefreshToken   string           `json:"refresh_token"`
		IDToken        string           `json:"-"`
		AccessTokenExp time.Time        `json:"access_token_exp"`
		UserInfo       UserInfoResponse `json:"user_info"`
		ReturnURL      string           `json:"-"`
		UserId         string           `json:"userId"`
		Name           string           `json:"name"`
		TenantID       string           `json:"tenantId"`
		IDPName        string           `json:"idpName"`
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

type WristbandApp struct {
	WristbandAuth
	LoginPath         string
	CallbackURL       string
	logoutRedirectURL string
	SessionManager    SessionManager
	cookieOpts        CookieOptions
	cookieEncryption  CookieEncryption
}

func (app WristbandApp) LoginEndpoint() string {
	return app.Domains.WristbandDomain + app.LoginPath
}

func (app WristbandApp) HttpContext(res http.ResponseWriter, req *http.Request) HttpContext {
	return &StandardHttp{
		req:              req,
		res:              res,
		cookieOpts:       app.cookieOpts,
		cookieEncryption: app.cookieEncryption,
	}
}

// LoginHandler creates a middleware for initiating a login request
func (app WristbandApp) LoginHandler(opts ...func(*LoginOptions)) http.HandlerFunc {
	options := DefaultLoginOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Cache-Control", "no-cache, no-store")
		res.Header().Set("Pragma", "no-cache")

		httpCtx := app.HttpContext(res, req)
		// Build authorization URL
		authURL, err := app.HandleLogin(httpCtx, app.CallbackURL, options)
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
		ctx := app.HttpContext(res, req)
		// Create session
		callbackContext, err := app.WristbandAuth.HandleCallback(ctx, app.CallbackURL)
		if err != nil {
			http.Error(res, "Failed to store session", http.StatusInternalServerError)
			return
		}

		// Store session using the session manager
		if err := app.SessionManager.StoreSession(req.Context(), res, req, callbackContext.Session()); err != nil {
			http.Error(res, "Failed to store session", http.StatusInternalServerError)
			return
		}

		// Clear login state cookie
		ctx.ClearCookie(callbackContext.LoginState.CookieName())

		// Redirect to return URL or default location
		redirectURL := "/"
		if url := callbackContext.LoginState.ReturnURL; url != "" {
			redirectURL = url
		}

		http.Redirect(res, req, redirectURL, http.StatusFound)
	}
}

// LogoutHandler creates a middleware for logging out users
func (app WristbandApp) LogoutHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		url := app.LogoutURL(req.URL.Query())
		// Get session from session manager
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			// If no session, just redirect to Wristband logout
			http.Redirect(res, req, url, http.StatusFound)
			return
		}

		// Try to revoke refresh token
		if session.RefreshToken != "" {
			_ = app.RevokeToken(session.RefreshToken, "refresh_token")
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

type SessionResponse struct {
	UserId   string `json:"userId"`
	TenantID string `json:"tenantId"`
	Metadata any    `json:"metadata"`
}

func (app WristbandApp) SessionHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			http.Error(res, "Unauthorized access: user not authenticated", http.StatusUnauthorized)
			return
		}
		if session.RefreshToken != "" {
			return
		}
		resp := SessionResponse{
			UserId:   session.UserId,
			TenantID: session.TenantID,
			Metadata: session.Name,
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			http.Error(res, "Unauthorized access: user not authenticated", http.StatusUnauthorized)
			return
		}
		res.Header().Set("Content-Type", "application/json")
		res.Write(respBytes)
	}
}
