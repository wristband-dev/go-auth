package goauth

import (
	"net/url"
	"slices"
	"strings"

	"github.com/wristband-dev/go-auth/rand"
)

type AuthorizeRequest struct {
	State        string
	Nonce        string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
	LoginHint    string
	Client       ConfidentialClient
	Domains      AppDomains
}

type AuthorizeRequestOption interface {
	apply(*AuthorizeRequest)
}

var defaultScopes = []string{"openid", "offline_access", "email"}

// NewAuthorizeRequest builds the authorization request for redirecting to Wristband
func (auth WristbandAuth) NewAuthorizeRequest(callbackURL, state string, opts ...AuthorizeRequestOption) *AuthorizeRequest {
	req := &AuthorizeRequest{
		State:        state,
		RedirectURI:  callbackURL,
		Scopes:       defaultScopes,
		Client:       auth.Client,
		Domains:      auth.Domains,
		CodeVerifier: rand.GenerateRandomString(32),
		Nonce:        rand.GenerateRandomString(32),
	}

	for _, opt := range opts {
		opt.apply(req)
	}
	return req
}

// AuthorizeURL returns the authorization URL for redirecting to Wristband
func (req AuthorizeRequest) AuthorizeURL(queryValues QueryValueResolver) string {
	endpoint := req.Domains.TenantedHost(queryValues) + DefaultAuthorizeEndpoint
	params := url.Values{}
	params.Set("client_id", req.Client.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(req.Scopes, " "))
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

	return endpoint + "?" + params.Encode()
}

func WithScopes(scopes ...string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		r.Scopes = scopes
	})
}

func WithAdditionalScopes(scopes ...string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		for _, scope := range scopes {
			if !slices.Contains(r.Scopes, scope) {
				r.Scopes = append(r.Scopes, scope)
			}
		}
	})
}

func WithNonce(nonce string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		r.Nonce = nonce
	})
}

func WithCodeVerifier(codeVerifier string) AuthorizeRequestOption {
	return authReqOptionFn(func(r *AuthorizeRequest) {
		r.CodeVerifier = codeVerifier
	})
}

type authReqOptionFn func(*AuthorizeRequest)

func (f authReqOptionFn) apply(c *AuthorizeRequest) {
	f(c)
}
