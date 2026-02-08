package goauth

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestNewAuthorizeRequest(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid", "offline_access"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := auth.NewAuthorizeRequest("state-abc")

	if req.State != "state-abc" {
		t.Errorf("Expected State %q, got %q", "state-abc", req.State)
	}
	if req.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("Expected RedirectURI from config, got %q", req.RedirectURI)
	}
	if req.Client.ClientID != "test-client" {
		t.Errorf("Expected ClientID %q, got %q", "test-client", req.Client.ClientID)
	}
	if req.Nonce == "" {
		t.Error("Nonce should be auto-generated")
	}
	if req.CodeVerifier == "" {
		t.Error("CodeVerifier should be auto-generated")
	}
}

func TestNewAuthorizeRequest_WithOptions(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := auth.NewAuthorizeRequest("state-xyz",
		WithScopes("openid", "profile", "email"),
		WithNonce("custom-nonce"),
		WithCodeVerifier("custom-verifier"),
	)

	if len(req.Scopes) != 3 || req.Scopes[1] != "profile" {
		t.Errorf("Expected scopes [openid profile email], got %v", req.Scopes)
	}
	if req.Nonce != "custom-nonce" {
		t.Errorf("Expected Nonce %q, got %q", "custom-nonce", req.Nonce)
	}
	if req.CodeVerifier != "custom-verifier" {
		t.Errorf("Expected CodeVerifier %q, got %q", "custom-verifier", req.CodeVerifier)
	}
}

func TestWithAdditionalScopes(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := auth.NewAuthorizeRequest("state",
		WithAdditionalScopes("profile", "email"),
	)

	if !hasAll(req.Scopes, "profile", "email") {
		t.Errorf("Expected additional scopes profile and email, got %v", req.Scopes)
	}
}

func hasAll[T comparable](slice []T, items ...T) bool {
	found := 0
	for _, v := range slice {
		if slices.Contains(items, v) {
			found++
		}
	}
	return found == len(items)

}

func TestWithAdditionalScopes_NoDuplicates(t *testing.T) {
	authConfig := &AuthConfig{
		ClientID:                         "test-client",
		ClientSecret:                     "test-secret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		Scopes:                           []string{"openid"},
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}
	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	req := auth.NewAuthorizeRequest("state",
		WithAdditionalScopes("openid", "profile"),
	)

	openIDCount := 0
	for _, s := range req.Scopes {
		if s == "openid" {
			openIDCount++
		}
	}
	if !slices.Contains(req.Scopes, "openid") {
		t.Errorf("openid should not be duplicated, found %d times in %v", openIDCount, req.Scopes)
	}
}

func TestAuthorizeURL(t *testing.T) {
	authReq := AuthorizeRequest{
		State:        "state-123",
		Nonce:        "nonce-456",
		CodeVerifier: "verifier-789",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "offline_access"},
		Client:       ConfidentialClient{ClientID: "my-client"},
	}

	mockCtx := newMockHTTPContext()
	authorizeURL := authReq.AuthorizeURL(mockCtx, "tenant1-app.wristband.dev")

	parsedURL, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("Failed to parse authorize URL: %v", err)
	}

	if parsedURL.Scheme != "https" {
		t.Errorf("Expected scheme https, got %s", parsedURL.Scheme)
	}
	if parsedURL.Host != "tenant1-app.wristband.dev" {
		t.Errorf("Expected host tenant1-app.wristband.dev, got %s", parsedURL.Host)
	}
	if !strings.Contains(parsedURL.Path, DefaultAuthorizeEndpoint) {
		t.Errorf("Expected path to contain %s, got %s", DefaultAuthorizeEndpoint, parsedURL.Path)
	}

	q := parsedURL.Query()
	if q.Get("client_id") != "my-client" {
		t.Errorf("Expected client_id my-client, got %s", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Errorf("Expected redirect_uri, got %s", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("Expected response_type code, got %s", q.Get("response_type"))
	}
	if q.Get("state") != "state-123" {
		t.Errorf("Expected state state-123, got %s", q.Get("state"))
	}
	if q.Get("nonce") != "nonce-456" {
		t.Errorf("Expected nonce nonce-456, got %s", q.Get("nonce"))
	}
	if q.Get("code_challenge") == "" {
		t.Error("Expected code_challenge to be present")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("Expected code_challenge_method S256, got %s", q.Get("code_challenge_method"))
	}
	if q.Get("scope") != "openid offline_access" {
		t.Errorf("Expected scope 'openid offline_access', got %q", q.Get("scope"))
	}
}

func TestAuthorizeURL_WithLoginHint(t *testing.T) {
	authReq := AuthorizeRequest{
		State:       "state-123",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid"},
		Client:      ConfidentialClient{ClientID: "my-client"},
	}

	mockCtx := newMockHTTPContext()
	mockCtx.queryValues.Set("login_hint", "user@example.com")

	authorizeURL := authReq.AuthorizeURL(mockCtx, "tenant1-app.wristband.dev")

	parsedURL, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("Failed to parse authorize URL: %v", err)
	}

	if parsedURL.Query().Get("login_hint") != "user@example.com" {
		t.Errorf("Expected login_hint user@example.com, got %s", parsedURL.Query().Get("login_hint"))
	}
}

func TestAuthorizeURL_WithoutCodeVerifier(t *testing.T) {
	authReq := AuthorizeRequest{
		State:       "state-123",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid"},
		Client:      ConfidentialClient{ClientID: "my-client"},
		// No CodeVerifier
	}

	mockCtx := newMockHTTPContext()
	authorizeURL := authReq.AuthorizeURL(mockCtx, "tenant1-app.wristband.dev")

	parsedURL, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("Failed to parse authorize URL: %v", err)
	}

	if parsedURL.Query().Get("code_challenge") != "" {
		t.Error("code_challenge should not be present without CodeVerifier")
	}
	if parsedURL.Query().Get("code_challenge_method") != "" {
		t.Error("code_challenge_method should not be present without CodeVerifier")
	}
}

func TestAuthorizeURL_WithoutNonce(t *testing.T) {
	authReq := AuthorizeRequest{
		State:       "state-123",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid"},
		Client:      ConfidentialClient{ClientID: "my-client"},
		// No Nonce
	}

	mockCtx := newMockHTTPContext()
	authorizeURL := authReq.AuthorizeURL(mockCtx, "tenant1-app.wristband.dev")

	parsedURL, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("Failed to parse authorize URL: %v", err)
	}

	if parsedURL.Query().Get("nonce") != "" {
		t.Error("nonce should not be present when empty")
	}
}
