package goauth

import (
	"fmt"
	"net/http"
	"testing"
)

// newTestAuth builds a WristbandAuth whose Wristband API calls are served by the supplied
// stub HTTP client, so no real network traffic occurs.
func newTestAuth(t *testing.T, stub *http.Client) WristbandAuth {
	t.Helper()

	authConfig := &AuthConfig{
		ClientID:                         "cid",
		ClientSecret:                     "csecret",
		WristbandApplicationVanityDomain: "app.wristband.dev",
		AutoConfigureEnabled:             false,
		SdkConfiguration: &SdkConfiguration{
			LoginURL:    "https://app.wristband.dev/login",
			RedirectURI: "https://app.example.com/callback",
		},
	}

	auth, err := authConfig.WristbandAuth()
	if err != nil {
		t.Fatalf("Failed to build WristbandAuth: %v", err)
	}
	auth.Client.httpClient = stub

	return auth
}

func TestValidateTenantCustomDomain_Valid(t *testing.T) {
	stub, calls := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":true}`})
	client := NewConfidentialClient("cid", "csecret", "app.wristband.dev")
	client.httpClient = stub

	valid, err := client.ValidateTenantCustomDomain("custom.acme.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected domain to be valid")
	}
	if calls.Load() != 1 {
		t.Errorf("Expected 1 request, got %d", calls.Load())
	}
}

func TestValidateTenantCustomDomain_Invalid(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":false}`})
	client := NewConfidentialClient("cid", "csecret", "app.wristband.dev")
	client.httpClient = stub

	valid, err := client.ValidateTenantCustomDomain("bogus.acme.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if valid {
		t.Error("Expected domain to be invalid")
	}
}

func TestValidateTenantCustomDomain_EmptyDomain(t *testing.T) {
	client := NewConfidentialClient("cid", "csecret", "app.wristband.dev")

	if _, err := client.ValidateTenantCustomDomain(""); err == nil {
		t.Error("Expected an error for an empty domain")
	}
	if _, err := client.ValidateTenantCustomDomain("   "); err == nil {
		t.Error("Expected an error for a whitespace-only domain")
	}
}

func TestValidateTenantCustomDomain_RetriesOn5xxThenSucceeds(t *testing.T) {
	stub, calls := stubHTTPClient(
		stubResponse{statusCode: 500, body: "Internal Server Error"},
		stubResponse{statusCode: 500, body: "Internal Server Error"},
		stubResponse{statusCode: 200, body: `{"valid":true}`},
	)
	client := NewConfidentialClient("cid", "csecret", "app.wristband.dev")
	client.httpClient = stub

	valid, err := client.ValidateTenantCustomDomain("custom.acme.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected domain to be valid")
	}
	if calls.Load() != 3 {
		t.Errorf("Expected 3 requests, got %d", calls.Load())
	}
}

func TestValidateTenantCustomDomain_DoesNotRetryOn4xx(t *testing.T) {
	stub, calls := stubHTTPClient(stubResponse{statusCode: 400, body: "Bad Request"})
	client := NewConfidentialClient("cid", "csecret", "app.wristband.dev")
	client.httpClient = stub

	if _, err := client.ValidateTenantCustomDomain("custom.acme.com"); err == nil {
		t.Fatal("Expected an error")
	}
	if calls.Load() != 1 {
		t.Errorf("Expected 1 request for a 4xx, got %d", calls.Load())
	}
}

// A 4xx whose body is not JSON must still surface as an APIError rather than a decoding
// failure, so that retry classification correctly treats it as non-retryable.
func TestValidateTenantCustomDomain_NonJSONErrorBodyIsNotRetried(t *testing.T) {
	stub, calls := stubHTTPClient(stubResponse{statusCode: 401, body: "<html>Unauthorized</html>"})
	client := NewConfidentialClient("cid", "csecret", "app.wristband.dev")
	client.httpClient = stub

	_, err := client.ValidateTenantCustomDomain("custom.acme.com")
	if err == nil {
		t.Fatal("Expected an error")
	}
	apiErr, ok := IsAPIError(err)
	if !ok {
		t.Fatalf("Expected an APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", apiErr.StatusCode)
	}
	if calls.Load() != 1 {
		t.Errorf("Expected 1 request for a non-JSON 4xx, got %d", calls.Load())
	}
}

func TestLoginBaseURL_SkipsUnverifiedTenantCustomDomain(t *testing.T) {
	stub, calls := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":false}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "bogus.acme.com")
	ctx.queryValues.Set("tenant_name", "acme")

	got, err := auth.loginBaseURL(ctx, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Falls through to tenant name resolution instead of using the unverified domain.
	if got != "acme-app.wristband.dev" {
		t.Errorf("Expected %q, got %q", "acme-app.wristband.dev", got)
	}
	if calls.Load() != 1 {
		t.Errorf("Expected the domain to be validated once, got %d calls", calls.Load())
	}
}

func TestLoginBaseURL_UnverifiedDomainWithNoFallbackReturnsTenantNotFound(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":false}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "bogus.acme.com")

	if _, err := auth.loginBaseURL(ctx, nil); err == nil {
		t.Fatal("Expected ErrTenantNameNotFound, got nil")
	}
}

func TestLoginBaseURL_DoesNotValidateWhenNoDomainParamPresent(t *testing.T) {
	stub, calls := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":true}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_name", "acme")

	if _, err := auth.loginBaseURL(ctx, nil); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if calls.Load() != 0 {
		t.Errorf("Expected no validation call, got %d", calls.Load())
	}
}

func TestLoginBaseURL_PropagatesValidationFailure(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 400, body: "Bad Request"})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "custom.acme.com")

	if _, err := auth.loginBaseURL(ctx, nil); err == nil {
		t.Fatal("Expected the validation error to propagate, got nil")
	}
}

func TestLogoutHost_UsesVerifiedTenantCustomDomain(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":true}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "custom.acme.com")

	got, err := auth.logoutHost(ctx, LogoutConfig{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "custom.acme.com" {
		t.Errorf("Expected %q, got %q", "custom.acme.com", got)
	}
}

func TestLogoutHost_SkipsUnverifiedTenantCustomDomain(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":false}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("tenant_custom_domain", "bogus.acme.com")
	ctx.queryValues.Set("tenant_name", "acme")

	got, err := auth.logoutHost(ctx, LogoutConfig{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Falls through to tenant name resolution instead of using the unverified domain.
	if got != "acme-app.wristband.dev" {
		t.Errorf("Expected %q, got %q", "acme-app.wristband.dev", got)
	}
}

// A tenant custom domain set directly in LogoutConfig by the developer is trusted and is not
// validated, since it cannot be manipulated by an external user.
func TestLogoutHost_DoesNotValidateConfigProvidedDomain(t *testing.T) {
	stub, calls := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":false}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()

	got, err := auth.logoutHost(ctx, LogoutConfig{tenantCustomDomain: "config.acme.com"})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "config.acme.com" {
		t.Errorf("Expected %q, got %q", "config.acme.com", got)
	}
	if calls.Load() != 0 {
		t.Errorf("Expected no validation call for a config-provided domain, got %d", calls.Load())
	}
}

func TestGetCallbackInputs_SkipsUnverifiedTenantCustomDomain(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":false}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code")
	ctx.queryValues.Set("tenant_custom_domain", "bogus.acme.com")
	ctx.queryValues.Set("tenant_name", "acme")

	inputs, err := auth.getCallbackInputs(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if inputs.TenantCustomDomain != "" {
		t.Errorf("Expected the unverified domain to be skipped, got %q", inputs.TenantCustomDomain)
	}
	if inputs.TenantName != "acme" {
		t.Errorf("Expected tenant name %q, got %q", "acme", inputs.TenantName)
	}
}

func TestGetCallbackInputs_KeepsVerifiedTenantCustomDomain(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 200, body: `{"valid":true}`})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code")
	ctx.queryValues.Set("tenant_custom_domain", "custom.acme.com")

	inputs, err := auth.getCallbackInputs(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if inputs.TenantCustomDomain != "custom.acme.com" {
		t.Errorf("Expected %q, got %q", "custom.acme.com", inputs.TenantCustomDomain)
	}
}

func TestGetCallbackInputs_PropagatesValidationFailure(t *testing.T) {
	stub, _ := stubHTTPClient(stubResponse{statusCode: 500, body: "Internal Server Error"})
	auth := newTestAuth(t, stub)

	ctx := newMockHTTPContext()
	ctx.queryValues.Set("code", "auth-code")
	ctx.queryValues.Set("tenant_custom_domain", "custom.acme.com")

	_, err := auth.getCallbackInputs(ctx)
	if err == nil {
		t.Fatal("Expected the validation error to propagate, got nil")
	}
	if _, ok := IsAPIError(err); !ok {
		t.Errorf("Expected an APIError, got %T: %v", err, fmt.Sprint(err))
	}
}
