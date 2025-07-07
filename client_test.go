package goauth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestNewConfidentialClient(t *testing.T) {
	clientID := "test-client-id"
	clientSecret := "test-client-secret"

	client := NewConfidentialClient(clientID, clientSecret)

	if client.ClientID != clientID {
		t.Errorf("Expected ClientID to be '%s', got %s", clientID, client.ClientID)
	}
	if client.ClientSecret != clientSecret {
		t.Errorf("Expected ClientSecret to be '%s', got %s", clientSecret, client.ClientSecret)
	}
}

func TestConfidentialClientSetRequestAuth(t *testing.T) {
	client := &ConfidentialClient{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	req := httptest.NewRequest("POST", "https://example.com/token", nil)

	client.SetRequestAuth(req)

	username, password, ok := req.BasicAuth()
	if !ok {
		t.Fatal("Expected basic auth to be set")
	}
	if username != "test-client-id" {
		t.Errorf("Expected username to be 'test-client-id', got %s", username)
	}
	if password != "test-client-secret" {
		t.Errorf("Expected password to be 'test-client-secret', got %s", password)
	}
}

func TestConfidentialClientSetRequestAuthWithEmptyCredentials(t *testing.T) {
	client := &ConfidentialClient{
		ClientID:     "",
		ClientSecret: "",
	}

	req := httptest.NewRequest("POST", "https://example.com/token", nil)

	client.SetRequestAuth(req)

	username, password, ok := req.BasicAuth()
	if !ok {
		t.Fatal("Expected basic auth to be set even with empty credentials")
	}
	if username != "" {
		t.Errorf("Expected empty username, got %s", username)
	}
	if password != "" {
		t.Errorf("Expected empty password, got %s", password)
	}
}

func TestConfidentialClientJSON(t *testing.T) {
	client := ConfidentialClient{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	// Test that the struct can be properly marshaled/unmarshaled
	// This tests the JSON tags on the struct fields

	data, err := json.Marshal(client)
	if err != nil {
		t.Fatalf("Failed to marshal ConfidentialClient: %v", err)
	}

	var unmarshaled ConfidentialClient
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal ConfidentialClient: %v", err)
	}

	if unmarshaled.ClientID != client.ClientID {
		t.Errorf("Expected ClientID to be '%s', got %s", client.ClientID, unmarshaled.ClientID)
	}
	if unmarshaled.ClientSecret != client.ClientSecret {
		t.Errorf("Expected ClientSecret to be '%s', got %s", client.ClientSecret, unmarshaled.ClientSecret)
	}

	// Verify the JSON structure
	expectedJSON := `{"client_id":"test-client-id","client_secret":"test-client-secret"}`
	if string(data) != expectedJSON {
		t.Errorf("Expected JSON '%s', got '%s'", expectedJSON, string(data))
	}
}

func TestConfidentialClientWithNilPointer(t *testing.T) {
	var client *ConfidentialClient

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling method on nil pointer")
		}
	}()

	req := httptest.NewRequest("POST", "https://example.com/token", nil)
	client.SetRequestAuth(req)
}
