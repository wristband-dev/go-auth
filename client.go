package goauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MaxFetchAttempts is the maximum number of attempts to fetch SDK configuration
const MaxFetchAttempts = 3

// AttemptDelayMs is the delay between retry attempts in milliseconds
const AttemptDelayMs = 100

// NewConfidentialClient creates a new ConfidentialClient with the provided client ID and secret.
func NewConfidentialClient(clientID, clientSecret, wristbandApplicationVanityDomain string) ConfidentialClient {
	return ConfidentialClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		WristbandApplicationVanityDomain: wristbandApplicationVanityDomain,
		httpClient: http.DefaultClient,
	}
}

// ConfidentialClient represents a confidential client with client ID and secret.
type ConfidentialClient struct {
	httpClient *http.Client
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	WristbandApplicationVanityDomain string `json:"wristband_application_vanity_domain"`
}

// SetRequestAuth sets the HTTP request's basic authentication using the client's credentials.
func (c *ConfidentialClient) SetRequestAuth(httpReq *http.Request) {
	httpReq.SetBasicAuth(c.ClientID, c.ClientSecret)
}

// GetSdkConfiguration fetches the SDK configuration from Wristband's auto-configuration endpoint
func (c *ConfidentialClient) GetSdkConfiguration() (*SdkConfiguration, error) {
	endpoint := fmt.Sprintf("https://%s/api/v1/sdk-configuration", c.WristbandApplicationVanityDomain)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	sdkConfig := &SdkConfiguration{
		LoginURL:                        response["loginUrl"].(string),
		RedirectURI:                     response["redirectUri"].(string),
		IsApplicationCustomDomainActive: response["isApplicationCustomDomainActive"].(bool),
	}

	if customLoginPageURL, ok := response["customApplicationLoginPageUrl"].(string); ok {
		sdkConfig.CustomApplicationLoginPageURL = customLoginPageURL
	}

	if tenantDomainSuffix, ok := response["loginUrlTenantDomainSuffix"].(string); ok {
		sdkConfig.LoginURLTenantDomainSuffix = tenantDomainSuffix
	}

	return sdkConfig, nil
}

