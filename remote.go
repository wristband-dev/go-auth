package goauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// UserInfoResponse represents the userinfo response from Wristband
type UserInfoResponse struct {
	Sub           string   `json:"sub"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	TenantID      string   `json:"tnt_id"`
	IDPName       string   `json:"idp_name"`
	Roles         []string `json:"roles"`
	// Add additional fields as needed
}

// getUserInfo fetches user information using the access token
func (auth WristbandAuth) getUserInfo(accessToken string) (UserInfoResponse, error) {
	userInfoEndpoint := fmt.Sprintf("https://%s", auth.UserInfoEndpoint())

	req, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		return UserInfoResponse{}, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := auth.httpClient.Do(req)
	if err != nil {
		return UserInfoResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserInfoResponse{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return UserInfoResponse{}, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, body)
	}

	var userInfo UserInfoResponse
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return UserInfoResponse{}, err
	}

	return userInfo, nil
}
