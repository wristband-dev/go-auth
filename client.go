package goauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MaxFetchAttempts is the maximum number of attempts to fetch SDK configuration.
//
// Deprecated: retries are now applied to every Wristband API call rather than only to the
// SDK configuration fetch. Use MaxAPIRetryAttempts instead.
const MaxFetchAttempts = 3

// AttemptDelayMs is the delay between retry attempts in milliseconds.
//
// Deprecated: retries are now applied to every Wristband API call and use exponential
// backoff. Use APIRetryDelayMs and APIRetryDelayMultiplier instead.
const AttemptDelayMs = 100

// NewConfidentialClient creates a new ConfidentialClient with the provided client ID and secret.
func NewConfidentialClient(clientID, clientSecret, wristbandApplicationVanityDomain string) ConfidentialClient {
	return ConfidentialClient{
		ClientID:                         clientID,
		ClientSecret:                     clientSecret,
		WristbandApplicationVanityDomain: wristbandApplicationVanityDomain,
		httpClient:                       http.DefaultClient,
	}
}

// ConfidentialClient represents a confidential client with client ID and secret.
type ConfidentialClient struct {
	httpClient                       *http.Client
	ClientID                         string `json:"client_id"`
	ClientSecret                     string `json:"client_secret"`
	WristbandApplicationVanityDomain string `json:"wristband_application_vanity_domain"`
}

// SetRequestAuth sets the HTTP request's basic authentication using the client's credentials.
func (c *ConfidentialClient) SetRequestAuth(httpReq *http.Request) {
	httpReq.SetBasicAuth(c.ClientID, c.ClientSecret)
}

// GetSdkConfiguration fetches the SDK configuration from Wristband's auto-configuration endpoint.
//
// Transient failures (5xx responses and network errors) are retried automatically with
// exponential backoff. See withRetry.
func (c *ConfidentialClient) GetSdkConfiguration() (*SdkConfiguration, error) {
	endpoint := fmt.Sprintf("https://%s/api/v1/clients/%s/sdk-configuration", c.WristbandApplicationVanityDomain, c.ClientID)

	return withRetry(func() (*SdkConfiguration, error) {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json;charset=UTF-8")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, &APIError{
				Operation:  "SDK configuration request",
				StatusCode: resp.StatusCode,
				Body:       string(body),
			}
		}

		var response map[string]any
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		sdkConfig := &SdkConfiguration{
			LoginURL:                        response["loginUrl"].(string),
			IsApplicationCustomDomainActive: response["isApplicationCustomDomainActive"].(bool),
		}

		if redirectURI, ok := response["redirectUri"].(string); ok {
			sdkConfig.RedirectURI = redirectURI
		}

		if customLoginPageURL, ok := response["customApplicationLoginPageUrl"].(string); ok {
			sdkConfig.CustomApplicationLoginPageURL = customLoginPageURL
		}

		if tenantDomainSuffix, ok := response["loginUrlTenantDomainSuffix"].(string); ok {
			sdkConfig.LoginURLTenantDomainSuffix = tenantDomainSuffix
		}

		return sdkConfig, nil
	})
}

// validateTenantCustomDomainResponse is the response body of the tenant custom domain
// validation endpoint.
type validateTenantCustomDomainResponse struct {
	Valid bool `json:"valid"`
}

// ValidateTenantCustomDomain reports whether the given tenant custom domain is verified and
// belongs to your Wristband application.
//
// This is used to confirm that a tenant custom domain supplied via query parameter is
// legitimate before the SDK redirects to it, which prevents external users from manipulating
// where the SDK sends them. Transient failures (5xx responses and network errors) are retried
// automatically with exponential backoff. See withRetry.
func (c *ConfidentialClient) ValidateTenantCustomDomain(tenantCustomDomain string) (bool, error) {
	if strings.TrimSpace(tenantCustomDomain) == "" {
		return false, fmt.Errorf("tenant custom domain is required")
	}

	endpoint := fmt.Sprintf("https://%s/api/v1/custom-domains/validate", c.WristbandApplicationVanityDomain)

	payload, err := json.Marshal(map[string]string{"tenantCustomDomain": tenantCustomDomain})
	if err != nil {
		return false, fmt.Errorf("failed to encode request: %w", err)
	}

	return withRetry(func() (bool, error) {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return false, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("failed to make request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return false, &APIError{
				Operation:  "tenant custom domain validation request",
				StatusCode: resp.StatusCode,
				Body:       string(body),
			}
		}

		var response validateTenantCustomDomainResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return false, fmt.Errorf("failed to decode response: %w", err)
		}

		return response.Valid, nil
	})
}
