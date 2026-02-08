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
func SessionFromContext(ctx context.Context) *Session {
	session, ok := ctx.Value(wristbandAuthContextKey{}).(*Session)
	if !ok {
		return nil
	}
	return session
}

// RefreshTokenIfExpired refreshes the access token if it's expired and
func (app WristbandApp) RefreshTokenIfExpired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// Get session from session manager
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			// No session, continue to next handler
			next.ServeHTTP(res, req)
			return
		}

		// Check if access token is expired or about to expire
		bufferDuration := time.Duration(app.configResolver.GetTokenExpirationBuffer()) * time.Second
		if time.Now().Add(bufferDuration).Before(session.ExpiresAt) {
			// Token is still valid, continue to next handler
			next.ServeHTTP(res, req)
			return
		}

		// Refresh token
		tokenResponse, err := app.RefreshAccessToken(session.RefreshToken)
		if err != nil {
			// Failed to refresh token, clear session and redirect to login
			_ = app.SessionManager.ClearSession(req.Context(), res, req)
			http.Redirect(res, req, app.configResolver.MustLoginURL()+"?return_url="+url.QueryEscape(req.URL.String()), http.StatusFound)
			return
		}

		// Update session with new tokens
		session.ExpiresIn = time.Second * time.Duration(tokenResponse.ExpiresIn)
		expiresAt := time.Now().Add(session.ExpiresIn)
		session.AccessToken = tokenResponse.AccessToken
		session.ExpiresAt = expiresAt
		if tokenResponse.RefreshToken != "" {
			session.RefreshToken = tokenResponse.RefreshToken
		}

		// Store updated session
		if err := app.SessionManager.StoreSession(req.Context(), res, req, session); err != nil {
			http.Error(res, "Failed to update session", http.StatusInternalServerError)
			return
		}

		// Continue to next handler
		next.ServeHTTP(res, req)
	})
}

// RequireAuthentication is a middleware that checks if the user is authenticated and sets the session in the context.
func (app WristbandApp) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// Get session from session manager
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			res.WriteHeader(http.StatusUnauthorized)
			return
		}
		req = req.WithContext(WithSessionContext(req.Context(), session))

		// User is authenticated, continue to next handler
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
