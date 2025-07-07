package go_auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewTokenRequest(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")
	config := TokenRequestConfig{
		Client:   client,
		Scopes:   []string{"read", "write"},
		Endpoint: "https://example.com/token",
	}

	req := NewTokenRequest(config)

	if req.Client.ClientID != "test-client-id" {
		t.Errorf("Expected Client.ClientID to be 'test-client-id', got %s", req.Client.ClientID)
	}
	if len(req.Scopes) != 2 || req.Scopes[0] != "read" || req.Scopes[1] != "write" {
		t.Errorf("Expected scopes [read write], got %v", req.Scopes)
	}
	if req.Endpoint != "https://example.com/token" {
		t.Errorf("Expected Endpoint to be 'https://example.com/token', got %s", req.Endpoint)
	}
}

func TestNewTokenRequestWithOptions(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")
	config := TokenRequestConfig{
		Client:   client,
		Endpoint: "https://example.com/token",
	}

	req := NewTokenRequest(config,
		WithRefreshToken("test-refresh-token"),
	)

	if req.GrantType != GrantTypeRefreshToken {
		t.Errorf("Expected GrantType to be '%s', got %s", GrantTypeRefreshToken, req.GrantType)
	}
	if req.RefreshToken != "test-refresh-token" {
		t.Errorf("Expected RefreshToken to be 'test-refresh-token', got %s", req.RefreshToken)
	}
}

func TestNewTokenRequestWithAuthCode(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")
	config := TokenRequestConfig{
		Client:   client,
		Endpoint: "https://example.com/token",
	}

	req := NewTokenRequest(config,
		WithAuthCode("test-code", "test-verifier", "http://localhost:8080/callback"),
	)

	if req.GrantType != GrantTypeCode {
		t.Errorf("Expected GrantType to be '%s', got %s", GrantTypeCode, req.GrantType)
	}
	if req.Code != "test-code" {
		t.Errorf("Expected Code to be 'test-code', got %s", req.Code)
	}
	if req.CodeVerifier != "test-verifier" {
		t.Errorf("Expected CodeVerifier to be 'test-verifier', got %s", req.CodeVerifier)
	}
	if req.RedirectURI != "http://localhost:8080/callback" {
		t.Errorf("Expected RedirectURI to be 'http://localhost:8080/callback', got %s", req.RedirectURI)
	}
}

func TestNewClientCredentialsTokenRequest(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	req := NewClientCredentialsTokenRequest(client, "https://example.com/token")

	if req.Client.ClientID != "test-client-id" {
		t.Errorf("Expected Client.ClientID to be 'test-client-id', got %s", req.Client.ClientID)
	}
	if req.Endpoint != "https://example.com/token" {
		t.Errorf("Expected Endpoint to be 'https://example.com/token', got %s", req.Endpoint)
	}
	if req.GrantType != GrantTypeClientCredentials {
		t.Errorf("Expected GrantType to be '%s', got %s", GrantTypeClientCredentials, req.GrantType)
	}
}

func TestTokenRequestValidate(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	testCases := []struct {
		name        string
		request     TokenRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid authorization code request",
			request: TokenRequest{
				GrantType:    GrantTypeCode,
				Client:       client,
				Endpoint:     "https://example.com/token",
				Code:         "test-code",
				RedirectURI:  "http://localhost:8080/callback",
				CodeVerifier: "test-verifier",
			},
			expectError: false,
		},
		{
			name: "valid refresh token request",
			request: TokenRequest{
				GrantType:    GrantTypeRefreshToken,
				Client:       client,
				Endpoint:     "https://example.com/token",
				RefreshToken: "test-refresh-token",
			},
			expectError: false,
		},
		{
			name: "valid client credentials request",
			request: TokenRequest{
				GrantType: GrantTypeClientCredentials,
				Client:    client,
				Endpoint:  "https://example.com/token",
			},
			expectError: false,
		},
		{
			name: "refresh token missing for refresh grant",
			request: TokenRequest{
				GrantType: GrantTypeRefreshToken,
				Client:    client,
				Endpoint:  "https://example.com/token",
			},
			expectError: true,
			errorMsg:    "refresh_token is required for refresh_token grant_type",
		},
		{
			name: "refresh token with wrong grant type",
			request: TokenRequest{
				GrantType:    GrantTypeCode,
				Client:       client,
				Endpoint:     "https://example.com/token",
				RefreshToken: "test-refresh-token",
			},
			expectError: true,
			errorMsg:    "refresh token is only supported for refresh_token grant_type",
		},
		{
			name: "code with wrong grant type",
			request: TokenRequest{
				GrantType:    GrantTypeRefreshToken,
				Client:       client,
				Endpoint:     "https://example.com/token",
				Code:         "test-code",
				RefreshToken: "someToken",
			},
			expectError: true,
			errorMsg:    "code is only supported for authorization_code grant_type",
		},
		{
			name: "scopes with client credentials",
			request: TokenRequest{
				GrantType: GrantTypeClientCredentials,
				Client:    client,
				Endpoint:  "https://example.com/token",
				Scopes:    []string{"read"},
			},
			expectError: true,
			errorMsg:    "scopes are not supported for client_credentials grant_type",
		},
		{
			name: "missing endpoint",
			request: TokenRequest{
				GrantType: GrantTypeCode,
				Client:    client,
			},
			expectError: true,
			errorMsg:    "token endpoint is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.request.Validate()
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error to contain '%s', got %s", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestTokenRequestDo(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Expected Content-Type 'application/x-www-form-urlencoded', got %s", r.Header.Get("Content-Type"))
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client-id" || password != "test-client-secret" {
			t.Errorf("Expected basic auth with test-client-id:test-client-secret")
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("Expected grant_type 'authorization_code', got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "test-code" {
			t.Errorf("Expected code 'test-code', got %s", r.Form.Get("code"))
		}
		if r.Form.Get("redirect_uri") != "http://localhost:8080/callback" {
			t.Errorf("Expected redirect_uri 'http://localhost:8080/callback', got %s", r.Form.Get("redirect_uri"))
		}
		if r.Form.Get("code_verifier") != "test-verifier" {
			t.Errorf("Expected code_verifier 'test-verifier', got %s", r.Form.Get("code_verifier"))
		}
		if r.Form.Get("scope") != "read write" {
			t.Errorf("Expected scope 'read write', got %s", r.Form.Get("scope"))
		}

		response := TokenResponse{
			AccessToken:  "test-access-token",
			TokenType:    "Bearer",
			RefreshToken: "test-refresh-token",
			IDToken:      "test-id-token",
			ExpiresIn:    3600,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	req := TokenRequest{
		GrantType:    GrantTypeCode,
		Client:       client,
		Scopes:       []string{"read", "write"},
		Endpoint:     server.URL,
		Code:         "test-code",
		CodeVerifier: "test-verifier",
		RedirectURI:  "http://localhost:8080/callback",
	}

	resp, err := req.Do(nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp.AccessToken != "test-access-token" {
		t.Errorf("Expected AccessToken 'test-access-token', got %s", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Expected TokenType 'Bearer', got %s", resp.TokenType)
	}
	if resp.RefreshToken != "test-refresh-token" {
		t.Errorf("Expected RefreshToken 'test-refresh-token', got %s", resp.RefreshToken)
	}
	if resp.IDToken != "test-id-token" {
		t.Errorf("Expected IDToken 'test-id-token', got %s", resp.IDToken)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected ExpiresIn 3600, got %d", resp.ExpiresIn)
	}
}

func TestTokenRequestDoRefreshToken(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("Expected grant_type 'refresh_token', got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "test-refresh-token" {
			t.Errorf("Expected refresh_token 'test-refresh-token', got %s", r.Form.Get("refresh_token"))
		}
		if r.Form.Get("scope") != "read write" {
			t.Errorf("Expected scope 'read write', got %s", r.Form.Get("scope"))
		}

		response := TokenResponse{
			AccessToken: "new-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	req := TokenRequest{
		GrantType:    GrantTypeRefreshToken,
		Client:       client,
		Scopes:       []string{"read", "write"},
		Endpoint:     server.URL,
		RefreshToken: "test-refresh-token",
	}

	resp, err := req.Do(nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp.AccessToken != "new-access-token" {
		t.Errorf("Expected AccessToken 'new-access-token', got %s", resp.AccessToken)
	}
}

func TestTokenRequestDoClientCredentials(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("Expected grant_type 'client_credentials', got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("scope") != "" {
			t.Errorf("Expected no scope for client_credentials, got %s", r.Form.Get("scope"))
		}

		response := TokenResponse{
			AccessToken: "client-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	req := NewClientCredentialsTokenRequest(client, server.URL)

	resp, err := req.Do(nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp.AccessToken != "client-access-token" {
		t.Errorf("Expected AccessToken 'client-access-token', got %s", resp.AccessToken)
	}
}

func TestTokenRequestDoWithCustomClient(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")
	customHTTPClient := &http.Client{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	req := TokenRequest{
		GrantType: GrantTypeClientCredentials,
		Client:    client,
		Endpoint:  server.URL,
	}

	resp, err := req.Do(customHTTPClient)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if resp.AccessToken != "test-access-token" {
		t.Errorf("Expected AccessToken 'test-access-token', got %s", resp.AccessToken)
	}
}

func TestTokenRequestDoValidationError(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	req := TokenRequest{
		GrantType:    GrantTypeRefreshToken,
		Client:       client,
		Endpoint:     "https://example.com/token",
		RefreshToken: "",
	}

	_, err := req.Do(nil)
	if err == nil {
		t.Fatal("Expected validation error")
	}
	if !strings.Contains(err.Error(), "refresh_token is required") {
		t.Errorf("Expected validation error message, got %s", err.Error())
	}
}

func TestTokenRequestDoHTTPError(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request"))
	}))
	defer server.Close()

	req := TokenRequest{
		GrantType: GrantTypeClientCredentials,
		Client:    client,
		Endpoint:  server.URL,
	}

	_, err := req.Do(nil)
	if err == nil {
		t.Fatal("Expected HTTP error")
	}
	if !strings.Contains(err.Error(), "token request failed with status 400") {
		t.Errorf("Expected HTTP error message, got %s", err.Error())
	}
}

func TestTokenRequestDoInvalidJSON(t *testing.T) {
	client := NewConfidentialClient("test-client-id", "test-client-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	req := TokenRequest{
		GrantType: GrantTypeClientCredentials,
		Client:    client,
		Endpoint:  server.URL,
	}

	_, err := req.Do(nil)
	if err == nil {
		t.Fatal("Expected JSON parsing error")
	}
}

func TestTokenRequestOptions(t *testing.T) {
	req := &TokenRequest{}

	t.Run("WithRefreshToken", func(t *testing.T) {
		opt := WithRefreshToken("test-refresh-token")
		opt(req)
		if req.GrantType != GrantTypeRefreshToken {
			t.Errorf("Expected GrantType to be '%s', got %s", GrantTypeRefreshToken, req.GrantType)
		}
		if req.RefreshToken != "test-refresh-token" {
			t.Errorf("Expected RefreshToken to be 'test-refresh-token', got %s", req.RefreshToken)
		}
	})

	t.Run("WithAuthCode", func(t *testing.T) {
		req = &TokenRequest{}
		opt := WithAuthCode("test-code", "test-verifier", "http://localhost:8080/callback")
		opt(req)
		if req.GrantType != GrantTypeCode {
			t.Errorf("Expected GrantType to be '%s', got %s", GrantTypeCode, req.GrantType)
		}
		if req.Code != "test-code" {
			t.Errorf("Expected Code to be 'test-code', got %s", req.Code)
		}
		if req.CodeVerifier != "test-verifier" {
			t.Errorf("Expected CodeVerifier to be 'test-verifier', got %s", req.CodeVerifier)
		}
		if req.RedirectURI != "http://localhost:8080/callback" {
			t.Errorf("Expected RedirectURI to be 'http://localhost:8080/callback', got %s", req.RedirectURI)
		}
	})
}
