package goauth

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type wristbandAuthContextKey struct{}

// WithSessionContext adds the session to the context.
func WithSessionContext(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, wristbandAuthContextKey{}, session)
}

// SessionFromContext retrieves the session from the context.
func SessionFromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(wristbandAuthContextKey{}).(*Session)
	if !ok {
		return Session{}, false
	}
	return *session, true
}

// Middlewares is a list of http handler middlewares.
type Middlewares []func(next http.Handler) http.Handler

// Apply returns an http.Handler with all the middlewares applied.
func (m Middlewares) Apply(next http.Handler) http.Handler {
	for _, middleware := range m {
		next = middleware(next)
	}
	return next
}

// RequireAuthentication middleware that checks if the user is authenticated and sets the session in the context
// and refreshes the access token if it's expired.
func (app WristbandApp) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// Get session from session manager
		session, err := app.SessionManager.GetSession(req)
		if err != nil {
			// No session, continue to next handler
			res.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if access token is expired or about to expire
		bufferDuration := time.Duration(app.configResolver.GetTokenExpirationBuffer()) * time.Second
		if time.Now().Add(bufferDuration).UnixMilli() < session.ExpiresAt {
			req = req.WithContext(WithSessionContext(req.Context(), session))
			// Token is still valid, continue to next handler
			next.ServeHTTP(res, req)
			return
		}

		// Refresh token
		tokenResponse, err := app.RefreshAccessToken(session.RefreshToken)
		if err != nil {
			// Failed to refresh token, clear session and redirect to login
			_ = app.SessionManager.ClearSession(res, req)
			http.Redirect(res, req, app.configResolver.MustLoginURL()+"?return_url="+url.QueryEscape(req.URL.String()), http.StatusFound)
			return
		}

		// Calculate token expiration buffer
		bufferSec := app.configResolver.GetTokenExpirationBuffer()
		tokenResponse.ExpiresIn -= bufferSec
		if tokenResponse.ExpiresIn < 0 {
			tokenResponse.ExpiresIn = 0
		}
		expiresIn := time.Second * time.Duration(tokenResponse.ExpiresIn)

		// Update session with new tokens
		session.AccessToken = tokenResponse.AccessToken
		session.ExpiresAt = time.Now().Add(expiresIn).UnixMilli()
		if tokenResponse.RefreshToken != "" {
			session.RefreshToken = tokenResponse.RefreshToken
		}
		req = req.WithContext(WithSessionContext(req.Context(), session))

		// Store updated session
		if err := app.SessionManager.StoreSession(res, req, session); err != nil {
			http.Error(res, "Failed to update session", http.StatusInternalServerError)
			return
		}

		// Continue to next handler
		next.ServeHTTP(res, req)
	})
}

// CacheControlMiddleware sets headers to prevent caching of responses.
func CacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid caching.
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}
