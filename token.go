package goauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// GrantTypeCode defines the grant_type `authorization_code` used for the Token Request in the Authorization Code Flow
	GrantTypeCode GrantType = "authorization_code"

	// GrantTypeRefreshToken defines the grant_type `refresh_token` used for the Token Request in the Refresh Token Flow
	GrantTypeRefreshToken GrantType = "refresh_token"

	// GrantTypeClientCredentials defines the grant_type `client_credentials` used for the Token Request in the Client Credentials Token Flow
	GrantTypeClientCredentials GrantType = "client_credentials"
)

type (
	// GrantType represents the type of OAuth grant being used
	GrantType string

	// TokenResponse represents the OAuth token response from Wristband
	TokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	TokenRequest struct {
		// GrantType is required.
		GrantType GrantType `json:"grant_type"`
		Client    ConfidentialClient

		// ---- Common request fields ----
		// Scopes are the requested scopes for the token.
		Scopes []string `json:"scopes"`
		// Endpoint is the token endpoint URL where the request should be sent.
		Endpoint string `json:"tokenEndpoint"`

		// ---- GrantTypeCode specific request fields ----

		// Code is required only for GrantTypeCode.
		Code string `json:"code"`
		// CodeVerifier is required only for GrantTypeCode with PKCE.
		// PKCE is used when code_challenge was specified in the original authorization request.
		CodeVerifier string `json:"code_verifier"`
		// RedirectURI should only be present for GrantTypeCode and if a redirect URI was provided in the original authorization request.
		RedirectURI string `json:"redirect_uri"`

		// ---- GrantTypeRefreshToken specific request fields ----

		// RefreshToken is the refresh token returned previously that can be used to obtain a new access token.
		// Required when using GrantTypeRefreshToken.
		// Refresh tokens are returned by a GrantTypeCode token request with offline_access scope set
		RefreshToken string `json:"refresh_token"`
	}

	// TokenRequestConfig holds common configuration for token requests.
	TokenRequestConfig struct {
		Client ConfidentialClient
		// Scopes are the requested scopes for the token.
		Scopes []string `json:"scopes"`
		// Endpoint is the token endpoint URL where the request should be sent.
		Endpoint string `json:"tokenEndpoint"`
	}

	// TokenRequestOption is a function that modifies a TokenRequest
	TokenRequestOption func(*TokenRequest)
)

// NewTokenRequest creates a new TokenRequest with the provided configuration and options.
func NewTokenRequest(cfg TokenRequestConfig, opts ...TokenRequestOption) TokenRequest {
	req := TokenRequest{
		Client:   cfg.Client,
		Scopes:   cfg.Scopes,
		Endpoint: cfg.Endpoint,
	}

	for _, opt := range opts {
		opt(&req)
	}

	return req
}

// WithRefreshToken returns a TokenRequestOption that sets the grant type to GrantTypeRefreshToken and sets the refresh token.
func WithRefreshToken(refreshToken string) TokenRequestOption {
	return func(req *TokenRequest) {
		req.GrantType = GrantTypeRefreshToken
		req.RefreshToken = refreshToken
	}
}

// WithAuthCode returns a TokenRequestOption for GrantTypeCode requests.
func WithAuthCode(code, codeVerifier, redirectURI string) TokenRequestOption {
	return func(req *TokenRequest) {
		req.GrantType = GrantTypeCode
		req.Code = code
		req.CodeVerifier = codeVerifier
		req.RedirectURI = redirectURI
	}
}

// NewClientCredentialsTokenRequest creates a TokenRequest for the client credentials grant type.
func NewClientCredentialsTokenRequest(client ConfidentialClient, endpoint string) TokenRequest {
	return NewTokenRequest(TokenRequestConfig{
		Client:   client,
		Endpoint: endpoint,
	}, func(req *TokenRequest) {
		req.GrantType = GrantTypeClientCredentials
	})
}

// Validate checks if the TokenRequest is valid based on the grant type and required fields.
func (req TokenRequest) Validate() error {
	if req.GrantType == GrantTypeRefreshToken {
		if req.RefreshToken == "" {
			return fmt.Errorf("refresh_token is required for refresh_token grant_type")
		}
	} else if req.RefreshToken != "" {
		return fmt.Errorf("refresh token is only supported for refresh_token grant_type")
	}

	if req.GrantType != GrantTypeCode {
		if len(req.Code) > 0 {
			return fmt.Errorf("code is only supported for authorization_code grant_type")
		}
	}
	if req.GrantType == GrantTypeClientCredentials {
		if len(req.Scopes) > 0 {
			return fmt.Errorf("scopes are not supported for client_credentials grant_type")
		}
	}

	if req.Endpoint == "" {
		return fmt.Errorf("token endpoint is required")
	}

	return nil
}

func (req TokenRequest) newHTTPRequest() (*http.Request, error) {
	data := url.Values{}
	data.Set("grant_type", string(req.GrantType))
	switch req.GrantType {
	case GrantTypeCode:
		data.Set("code", req.Code)
		data.Set("redirect_uri", req.RedirectURI)
		if req.CodeVerifier != "" {
			data.Set("code_verifier", req.CodeVerifier)
		}
	case GrantTypeRefreshToken:
		data.Set("refresh_token", req.RefreshToken)
	case GrantTypeClientCredentials:
		// No additional fields needed for client_credentials
	default:
		return nil, fmt.Errorf("invalid grant_type %s", req.GrantType)
	}
	if len(req.Scopes) > 0 {
		data.Set("scope", strings.Join(req.Scopes, " "))
	}
	httpReq, err := http.NewRequest(http.MethodPost, req.Endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Client.SetRequestAuth(httpReq)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httpReq, nil
}

// Do sends the TokenRequest and returns the TokenResponse.
func (req TokenRequest) Do(httpClient *http.Client) (TokenResponse, error) {
	// Validate the request before sending
	if err := req.Validate(); err != nil {
		return TokenResponse{}, err
	}

	// Use default HTTP client if none provided
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Create the HTTP request
	httpReq, err := req.newHTTPRequest()
	if err != nil {
		return TokenResponse{}, err
	}

	// Send the request
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return TokenResponse{}, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TokenResponse{}, err
	}

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, body)
	}

	// Parse the token response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}

// RefreshAccessToken refreshes an access token using a refresh token.
func (auth WristbandAuth) RefreshAccessToken(refreshToken string, scopes ...string) (TokenResponse, error) {
	req := NewTokenRequest(TokenRequestConfig{
		Client:   auth.Client,
		Endpoint: auth.tokenURL,
		Scopes:   scopes,
	}, WithRefreshToken(refreshToken))
	return req.Do(auth.httpClient)
}

// RevokeToken revokes a token (access or refresh)
func (auth WristbandAuth) RevokeToken(token, tokenType string) error {
	revokeEndpoint := fmt.Sprintf("https://%s", auth.RevokeEndpoint())

	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", tokenType)

	req, err := http.NewRequest(http.MethodPost, revokeEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	auth.Client.SetRequestAuth(req)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := auth.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token revocation failed with status %d: %s", resp.StatusCode, body)
	}

	return nil
}
