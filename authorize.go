package goauth

import (
	"fmt"
	"log"
	"net/url"
	"slices"
	"strings"

	"github.com/wristband-dev/go-auth/rand"
)

// AuthorizeRequest represents the parameters needed to build an authorization request.
type AuthorizeRequest struct {
	// State is a unique string to maintain state between the request and callback.
	State string
	// Nonce is a unique string used to mitigate replay attacks in OpenID Connect.
	Nonce string
	// CodeVerifier is used for PKCE (Proof Key for Code Exchange) to enhance security.
	CodeVerifier string
	// RedirectURI is the URL to which the user will be redirected after authorization.
	RedirectURI string
	// Scopes are the requested scopes for the authorization.
	Scopes []string
	// Client contains the client credentials for the OAuth application.
	Client ConfidentialClient
}

// AuthorizeRequestOption is an interface for options that can be applied to an AuthorizeRequest.
type AuthorizeRequestOption interface {
	apply(*AuthorizeRequest)
}

var defaultScopes = []string{"openid", "offline_access", "email"}

// NewAuthorizeRequest builds the authorization request for redirecting to Wristband
func (auth WristbandAuth) NewAuthorizeRequest(state string, opts ...AuthorizeRequestOption) *AuthorizeRequest {
	req := &AuthorizeRequest{
		State:        state,
		RedirectURI:  auth.configResolver.GetRedirectURI(),
		Scopes:       auth.configResolver.GetScopes(),
		Client:       auth.Client,
		CodeVerifier: rand.GenerateRandomString(32),
	}

	for _, opt := range opts {
		opt.apply(req)
	}
	if req.Nonce == "" {
		req.Nonce = rand.GenerateRandomString(32)
	}
	return req
}

// AuthorizeURL returns the authorization URL for redirecting to Wristband
func (req AuthorizeRequest) AuthorizeURL(httpCtx HTTPContext, baseUrl string) string {
	queryValues := httpCtx.Query()

	params := url.Values{}
	params.Set("client_id", req.Client.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(req.Scopes, " "))
	params.Set("state", req.State)
	if req.Nonce != "" {
		params.Set("nonce", req.Nonce)
	}
	if queryValues != nil && queryValues.Has("login_hint") {
		params.Set("login_hint", queryValues.Get("login_hint"))
	}
	if req.CodeVerifier != "" {
		// Generate code challenge for PKCE
		params.Set("code_challenge", rand.GenerateCodeChallenge(req.CodeVerifier))
		params.Set("code_challenge_method", "S256")
	}

	endpoint := fmt.Sprintf("https://%s/api/v1%s?%s", baseUrl, DefaultAuthorizeEndpoint, params.Encode())
	log.Printf("Authorize URL: %s\n", endpoint)

	return endpoint
}

// WithScopes sets the scopes for an AuthorizeRequest.
func WithScopes(scopes ...string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		r.Scopes = scopes
	})
}

// WithAdditionalScopes appends scopes to the current scopes of the AuthorizeRequest.
func WithAdditionalScopes(scopes ...string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		for _, scope := range scopes {
			if !slices.Contains(r.Scopes, scope) {
				r.Scopes = append(r.Scopes, scope)
			}
		}
	})
}

// WithNonce sets the nonce for an AuthorizeRequest.
func WithNonce(nonce string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		r.Nonce = nonce
	})
}

// WithCodeVerifier sets the code verifier for an AuthorizeRequest.
func WithCodeVerifier(codeVerifier string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		r.CodeVerifier = codeVerifier
	})
}

type authReqOptionFn func(*AuthorizeRequest)

func (f authReqOptionFn) apply(c *AuthorizeRequest) {
	f(c)
}
