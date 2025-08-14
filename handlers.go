package goauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type (
	// Session represents the user session after successful authentication
	Session struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"-"`
		// AccessTokenExp is the expiration time of the access token.
		AccessTokenExp time.Time        `json:"access_token_exp"`
		ExpiresIn      time.Duration    `json:"expiresIn"`
		UserInfo       UserInfoResponse `json:"user_info"`
		ReturnURL      string           `json:"-"`
		UserID         string           `json:"userID"`
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

// AppInput is the input structure for configuring the WristbandApp.
type AppInput struct {
	LoginPath                string
	CallbackURL              string
	SessionManager           SessionManager
	SessionMetadataExtractor func(Session) any
}

// NewApp returns a new WristbandApp instance with the provided configuration.
func NewApp(auth WristbandAuth, input AppInput, opts ...AppOption) WristbandApp {
	app := &WristbandApp{
		WristbandAuth:            auth,
		LoginPath:                input.LoginPath,
		CallbackURL:              input.CallbackURL,
		SessionManager:           input.SessionManager,
		sessionMetadataExtractor: input.SessionMetadataExtractor,
	}
	for _, opt := range opts {
		opt.apply(app)
	}

	return *app
}

// AppOption is an interface for options that can be applied to modify the WristbandApp configuration.
type AppOption interface {
	apply(*WristbandApp)
}

// WithCookieOptions sets the cookie configuration for the app.
func WithCookieOptions(cookieOpts CookieOptions) AppOption {
	return appOptionFunc(func(c *WristbandApp) {
		c.cookieOpts = cookieOpts
	})
}

type appOptionFunc func(*WristbandApp)

func (f appOptionFunc) apply(c *WristbandApp) {
	f(c)
}

// WristbandApp extends the WristbandAuth with additional standard library http.Handler functionality.
type WristbandApp struct {
	WristbandAuth
	LoginPath                string
	CallbackURL              string
	SessionManager           SessionManager
	cookieOpts               CookieOptions
	sessionMetadataExtractor func(Session) any
}

// LoginEndpoint returns the full URL for the login endpoint.
func (app WristbandApp) LoginEndpoint() string {
	return app.Domains.WristbandDomain + app.LoginPath
}

// HTTPContext creates a new HTTPContext for the standard library request and response.
func (app WristbandApp) HTTPContext(res http.ResponseWriter, req *http.Request) HTTPContext {
	return &StandardHTTP{
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

		if domains := app.Domains.RequestTenantDomains(req.URL.Query()); domains == nil || domains.TenantDomain == "" {
			// If tenant domain is not provided or defaulted, redirect to application login endpoint
			http.Redirect(res, req, fmt.Sprintf(`https://%s/login`, app.Domains.WristbandDomain), http.StatusFound)
		}

		httpCtx := app.HTTPContext(res, req)
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
		ctx := app.HTTPContext(res, req)
		// Create session
		callbackContext, err := app.HandleCallback(ctx, app.CallbackURL)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(res, "Failed to handle callback", http.StatusInternalServerError)
			return
		}

		// Store session using the session manager
		if err := app.SessionManager.StoreSession(req.Context(), res, req, callbackContext.Session()); err != nil {
			fmt.Println(err.Error())
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

// SessionResponse is the structure returned by the SessionHandler.
type SessionResponse struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	Metadata any    `json:"metadata"`
}

// SessionHandler is an http.HandlerFunc that retrieves the current user session.
func (app WristbandApp) SessionHandler() http.HandlerFunc {
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
		if app.sessionMetadataExtractor != nil {
			resp.Metadata = app.sessionMetadataExtractor(*session)
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
