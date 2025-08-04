package goauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type wristbandAuthContextKey struct{}

func WithSessionContext(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, wristbandAuthContextKey{}, session)
}

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
		fmt.Println("refresh middleware")
		// Get session from session manager
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			// No session, continue to next handler
			next.ServeHTTP(res, req)
			return
		}

		// Check if access token is expired or about to expire
		bufferDuration := time.Duration(app.tokenExpiryBuffer) * time.Second
		if time.Now().Add(bufferDuration).Before(session.AccessTokenExp) {
			// Token is still valid, continue to next handler
			next.ServeHTTP(res, req)
			return
		}

		// Refresh token
		tokenResponse, err := app.RefreshAccessToken(session.RefreshToken)
		if err != nil {
			// Failed to refresh token, clear session and redirect to login
			_ = app.SessionManager.ClearSession(req.Context(), res, req)
			http.Redirect(res, req, app.LoginEndpoint()+"?return_url="+url.QueryEscape(req.URL.Path), http.StatusFound)
			return
		}

		// Update session with new tokens
		expiresAt := time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn))
		session.AccessToken = tokenResponse.AccessToken
		session.AccessTokenExp = expiresAt
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

func (app WristbandApp) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// Get session from session manager
		session, err := app.SessionManager.GetSession(req.Context(), req)
		if err != nil {
			// No session, redirect to login with return URL
			returnURL := url.QueryEscape(req.URL.Path)
			redirectURL := app.LoginEndpoint()
			if !strings.Contains(redirectURL, "?") {
				redirectURL += "?"
			} else {
				redirectURL += "&"
			}
			redirectURL += "return_url=" + returnURL

			http.Redirect(res, req, redirectURL, http.StatusFound)
			return
		}
		req.WithContext(WithSessionContext(req.Context(), session))

		// User is authenticated, continue to next handler
		next.ServeHTTP(res, req)
	})
}

func CacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid caching.
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}
