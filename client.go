package goauth

import (
	"net/http"
)

func NewConfidentialClient(clientID, clientSecret string) ConfidentialClient {
	return ConfidentialClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

type ConfidentialClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (c *ConfidentialClient) SetRequestAuth(httpReq *http.Request) {
	httpReq.SetBasicAuth(c.ClientID, c.ClientSecret)
}
