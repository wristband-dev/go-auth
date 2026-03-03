package goauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test UserInfoResponse struct

func TestUserInfoResponse_JSONMarshaling(t *testing.T) {
	userInfo := UserInfoResponse{
		Sub:           "test-user-123",
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: true,
		TenantId:      "tenant-123",
		IdpName:       "google",
		Roles:         []string{"admin", "user"},
		CustomClaims: map[string]any{
			"department": "engineering",
			"level":      5,
			"active":     true,
		},
	}

	// Test marshaling
	data, err := json.Marshal(userInfo)
	if err != nil {
		t.Fatalf("Failed to marshal UserInfoResponse: %v", err)
	}

	// Test unmarshaling
	var unmarshaled UserInfoResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal UserInfoResponse: %v", err)
	}

	// Verify all fields
	if unmarshaled.Sub != userInfo.Sub {
		t.Errorf("Expected Sub %s, got %s", userInfo.Sub, unmarshaled.Sub)
	}
	if unmarshaled.Name != userInfo.Name {
		t.Errorf("Expected Name %s, got %s", userInfo.Name, unmarshaled.Name)
	}
	if unmarshaled.Email != userInfo.Email {
		t.Errorf("Expected Email %s, got %s", userInfo.Email, unmarshaled.Email)
	}
	if unmarshaled.EmailVerified != userInfo.EmailVerified {
		t.Errorf("Expected EmailVerified %v, got %v", userInfo.EmailVerified, unmarshaled.EmailVerified)
	}
	if unmarshaled.TenantId != userInfo.TenantId {
		t.Errorf("Expected TenantId %s, got %s", userInfo.TenantId, unmarshaled.TenantId)
	}
	if unmarshaled.IdpName != userInfo.IdpName {
		t.Errorf("Expected IdpName %s, got %s", userInfo.IdpName, unmarshaled.IdpName)
	}

	// Verify roles
	if len(unmarshaled.Roles) != len(userInfo.Roles) {
		t.Errorf("Expected %d roles, got %d", len(userInfo.Roles), len(unmarshaled.Roles))
	}
	for i, role := range userInfo.Roles {
		if unmarshaled.Roles[i] != role {
			t.Errorf("Expected role %s at index %d, got %s", role, i, unmarshaled.Roles[i])
		}
	}

	// Verify custom claims
	if len(unmarshaled.CustomClaims) != len(userInfo.CustomClaims) {
		t.Errorf("Expected %d custom claims, got %d", len(userInfo.CustomClaims), len(unmarshaled.CustomClaims))
	}
	if unmarshaled.CustomClaims["department"] != "engineering" {
		t.Errorf("Expected department 'engineering', got %v", unmarshaled.CustomClaims["department"])
	}
	if unmarshaled.CustomClaims["level"] != float64(5) { // JSON numbers become float64
		t.Errorf("Expected level 5, got %v", unmarshaled.CustomClaims["level"])
	}
	if unmarshaled.CustomClaims["active"] != true {
		t.Errorf("Expected active true, got %v", unmarshaled.CustomClaims["active"])
	}
}

func TestUserInfoResponse_JSONTags(t *testing.T) {
	userInfo := UserInfoResponse{
		Sub:           "test-user",
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: true,
		TenantId:      "tenant-123",
		IdpName:       "google",
		Roles:         []string{"user"},
		CustomClaims:  map[string]any{"key": "value"},
	}

	data, err := json.Marshal(userInfo)
	if err != nil {
		t.Fatalf("Failed to marshal UserInfoResponse: %v", err)
	}

	jsonStr := string(data)

	// Verify JSON field names match the tags
	expectedFields := []string{
		`"sub":"test-user"`,
		`"name":"Test User"`,
		`"email":"test@example.com"`,
		`"email_verified":true`,
		`"tnt_id":"tenant-123"`,
		`"idp_name":"google"`,
		`"roles":["user"]`,
		`"custom_claims":{"key":"value"}`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected JSON to contain %s, but got: %s", field, jsonStr)
		}
	}
}

func TestUserInfoResponse_EmptyFields(t *testing.T) {
	userInfo := UserInfoResponse{}

	data, err := json.Marshal(userInfo)
	if err != nil {
		t.Fatalf("Failed to marshal empty UserInfoResponse: %v", err)
	}

	var unmarshaled UserInfoResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal empty UserInfoResponse: %v", err)
	}

	// Verify empty values
	if unmarshaled.Sub != "" {
		t.Errorf("Expected empty Sub, got %s", unmarshaled.Sub)
	}
	if unmarshaled.EmailVerified {
		t.Error("Expected EmailVerified to be false")
	}
	if len(unmarshaled.Roles) != 0 {
		t.Errorf("Expected empty Roles slice, got %v", unmarshaled.Roles)
	}
	if len(unmarshaled.CustomClaims) != 0 {
		t.Errorf("Expected empty CustomClaims map, got %v", unmarshaled.CustomClaims)
	}
}

func TestUserInfoResponse_NilCustomClaims(t *testing.T) {
	userInfo := UserInfoResponse{
		Sub:          "test-user",
		CustomClaims: nil,
	}

	data, err := json.Marshal(userInfo)
	if err != nil {
		t.Fatalf("Failed to marshal UserInfoResponse with nil CustomClaims: %v", err)
	}

	var unmarshaled UserInfoResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal UserInfoResponse with nil CustomClaims: %v", err)
	}

	if unmarshaled.CustomClaims != nil {
		t.Error("Expected CustomClaims to remain nil")
	}
}

// Test getUserInfo method

func TestWristbandAuth_getUserInfo_Success(t *testing.T) {
	// Create test server (TLS for HTTPS)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and headers
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer test-access-token"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header %s, got %s", expectedAuth, authHeader)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", contentType)
		}

		accept := r.Header.Get("Accept")
		if accept != "application/json" {
			t.Errorf("Expected Accept application/json, got %s", accept)
		}

		// Return mock user info
		userInfo := UserInfoResponse{
			Sub:           "user-123",
			Name:          "John Doe",
			Email:         "john@example.com",
			EmailVerified: true,
			TenantId:      "tenant-123",
			IdpName:       "google",
			Roles:         []string{"admin", "user"},
			CustomClaims: map[string]any{
				"department": "engineering",
				"level":      5,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	// Create WristbandAuth with test server
	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	// Call getUserInfo
	userInfo, err := auth.getUserInfo("test-access-token")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify response
	if userInfo.Sub != "user-123" {
		t.Errorf("Expected Sub 'user-123', got %s", userInfo.Sub)
	}
	if userInfo.Name != "John Doe" {
		t.Errorf("Expected Name 'John Doe', got %s", userInfo.Name)
	}
	if userInfo.Email != "john@example.com" {
		t.Errorf("Expected Email 'john@example.com', got %s", userInfo.Email)
	}
	if !userInfo.EmailVerified {
		t.Error("Expected EmailVerified to be true")
	}
	if userInfo.TenantId != "tenant-123" {
		t.Errorf("Expected TenantId 'tenant-123', got %s", userInfo.TenantId)
	}
	if userInfo.IdpName != "google" {
		t.Errorf("Expected IdpName 'google', got %s", userInfo.IdpName)
	}

	expectedRoles := []string{"admin", "user"}
	if len(userInfo.Roles) != len(expectedRoles) {
		t.Errorf("Expected %d roles, got %d", len(expectedRoles), len(userInfo.Roles))
	}
	for i, role := range expectedRoles {
		if userInfo.Roles[i] != role {
			t.Errorf("Expected role %s at index %d, got %s", role, i, userInfo.Roles[i])
		}
	}

	if userInfo.CustomClaims["department"] != "engineering" {
		t.Errorf("Expected department 'engineering', got %v", userInfo.CustomClaims["department"])
	}
	if userInfo.CustomClaims["level"] != float64(5) {
		t.Errorf("Expected level 5, got %v", userInfo.CustomClaims["level"])
	}
}

func TestWristbandAuth_getUserInfo_HTTPError(t *testing.T) {
	// Create test server that returns an error
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	userInfo, err := auth.getUserInfo("invalid-token")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	expectedError := "userinfo request failed with status 401: Unauthorized"
	if err.Error() != expectedError {
		t.Errorf("Expected error %s, got %s", expectedError, err.Error())
	}

	// Verify empty response
	if userInfo.Sub != "" {
		t.Errorf("Expected empty UserInfoResponse, got %+v", userInfo)
	}
}

func TestWristbandAuth_getUserInfo_InvalidJSON(t *testing.T) {
	// Create test server that returns invalid JSON
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	userInfo, err := auth.getUserInfo("test-token")
	if err == nil {
		t.Fatal("Expected JSON unmarshal error, got nil")
	}

	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("Expected JSON unmarshal error, got %s", err.Error())
	}

	// Verify empty response
	if userInfo.Sub != "" {
		t.Errorf("Expected empty UserInfoResponse, got %+v", userInfo)
	}
}

func TestWristbandAuth_getUserInfo_NetworkError(t *testing.T) {
	// Use an invalid URL to simulate network error
	auth := WristbandAuth{
		endpointRoot:     "invalid-host.invalid",
		userInfoEndpoint: "/userinfo",
		httpClient:       &http.Client{},
	}

	userInfo, err := auth.getUserInfo("test-token")
	if err == nil {
		t.Fatal("Expected network error, got nil")
	}

	// Verify empty response
	if userInfo.Sub != "" {
		t.Errorf("Expected empty UserInfoResponse, got %+v", userInfo)
	}
}

func TestWristbandAuth_getUserInfo_EmptyToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer"
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization header '%s', got '%s'", expectedAuth, authHeader)
		}

		userInfo := UserInfoResponse{Sub: "user-123"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	userInfo, err := auth.getUserInfo("")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if userInfo.Sub != "user-123" {
		t.Errorf("Expected Sub 'user-123', got %s", userInfo.Sub)
	}
}

func TestWristbandAuth_getUserInfo_RequestCreationError(t *testing.T) {
	// This test is harder to trigger since http.NewRequest rarely fails
	// We'll test with a valid scenario but verify the request is created correctly
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the URL path
		expectedPath := "/api/v1/oauth2/userinfo"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		userInfo := UserInfoResponse{Sub: "user-123"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost + "/api/v1",
		userInfoEndpoint: "/oauth2/userinfo",
		httpClient:       server.Client(),
	}

	userInfo, err := auth.getUserInfo("test-token")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if userInfo.Sub != "user-123" {
		t.Errorf("Expected Sub 'user-123', got %s", userInfo.Sub)
	}
}

func TestWristbandAuth_getUserInfo_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	userInfo, err := auth.getUserInfo("test-token")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	expectedError := "userinfo request failed with status 500: Internal Server Error"
	if err.Error() != expectedError {
		t.Errorf("Expected error %s, got %s", expectedError, err.Error())
	}

	if userInfo.Sub != "" {
		t.Errorf("Expected empty UserInfoResponse, got %+v", userInfo)
	}
}

func TestWristbandAuth_getUserInfo_RedirectResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/login")
		w.WriteHeader(http.StatusFound)
		w.Write([]byte("Redirecting"))
	}))
	defer server.Close()

	// Create a client that doesn't follow redirects
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       client,
	}

	userInfo, err := auth.getUserInfo("test-token")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	expectedError := "userinfo request failed with status 302: Redirecting"
	if err.Error() != expectedError {
		t.Errorf("Expected error %s, got %s", expectedError, err.Error())
	}

	if userInfo.Sub != "" {
		t.Errorf("Expected empty UserInfoResponse, got %+v", userInfo)
	}
}

func TestWristbandAuth_getUserInfo_LargeResponse(t *testing.T) {
	// Test with a large custom claims object
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		largeClaims := make(map[string]any)
		for i := 0; i < 1000; i++ {
			largeClaims[fmt.Sprintf("claim_%d", i)] = fmt.Sprintf("value_%d", i)
		}

		userInfo := UserInfoResponse{
			Sub:          "user-123",
			Name:         "Test User",
			CustomClaims: largeClaims,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	userInfo, err := auth.getUserInfo("test-token")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if userInfo.Sub != "user-123" {
		t.Errorf("Expected Sub 'user-123', got %s", userInfo.Sub)
	}

	if len(userInfo.CustomClaims) != 1000 {
		t.Errorf("Expected 1000 custom claims, got %d", len(userInfo.CustomClaims))
	}

	// Verify a few claims
	if userInfo.CustomClaims["claim_0"] != "value_0" {
		t.Errorf("Expected claim_0 'value_0', got %v", userInfo.CustomClaims["claim_0"])
	}
	if userInfo.CustomClaims["claim_999"] != "value_999" {
		t.Errorf("Expected claim_999 'value_999', got %v", userInfo.CustomClaims["claim_999"])
	}
}

// Benchmark tests

func BenchmarkUserInfoResponse_JSONMarshaling(b *testing.B) {
	userInfo := UserInfoResponse{
		Sub:           "user-123",
		Name:          "John Doe",
		Email:         "john@example.com",
		EmailVerified: true,
		TenantId:      "tenant-123",
		IdpName:       "google",
		Roles:         []string{"admin", "user", "viewer"},
		CustomClaims: map[string]any{
			"department": "engineering",
			"level":      5,
			"active":     true,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(userInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUserInfoResponse_JSONUnmarshaling(b *testing.B) {
	userInfo := UserInfoResponse{
		Sub:           "user-123",
		Name:          "John Doe",
		Email:         "john@example.com",
		EmailVerified: true,
		TenantId:      "tenant-123",
		IdpName:       "google",
		Roles:         []string{"admin", "user", "viewer"},
		CustomClaims: map[string]any{
			"department": "engineering",
			"level":      5,
			"active":     true,
		},
	}

	data, err := json.Marshal(userInfo)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var unmarshaled UserInfoResponse
		err := json.Unmarshal(data, &unmarshaled)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWristbandAuth_getUserInfo(b *testing.B) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := UserInfoResponse{
			Sub:           "user-123",
			Name:          "John Doe",
			Email:         "john@example.com",
			EmailVerified: true,
			TenantId:      "tenant-123",
			IdpName:       "google",
			Roles:         []string{"admin", "user"},
			CustomClaims: map[string]any{
				"department": "engineering",
				"level":      5,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "https://")
	auth := WristbandAuth{
		endpointRoot:     serverHost,
		userInfoEndpoint: "",
		httpClient:       server.Client(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.getUserInfo("test-access-token")
		if err != nil {
			b.Fatal(err)
		}
	}
}
