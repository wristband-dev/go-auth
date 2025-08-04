package goauth

import (
	"net/http"
)

// NewConfidentialClient creates a new ConfidentialClient with the provided client ID and secret.
func NewConfidentialClient(clientID, clientSecret string) ConfidentialClient {
	return ConfidentialClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

// ConfidentialClient represents a confidential client with client ID and secret.
type ConfidentialClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// SetRequestAuth sets the HTTP request's basic authentication using the client's credentials.
func (c *ConfidentialClient) SetRequestAuth(httpReq *http.Request) {
	httpReq.SetBasicAuth(c.ClientID, c.ClientSecret)
}
