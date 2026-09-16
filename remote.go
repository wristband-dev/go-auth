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
	TenantId      string   `json:"tnt_id"`
	IdpName       string   `json:"idp_name"`
	Roles         []string `json:"roles"`
	// Add additional fields as needed
	CustomClaims map[string]any `json:"custom_claims"`
}

// getUserInfo fetches user information using the access token.
//
// Transient failures (5xx responses and network errors) are retried automatically with
// exponential backoff. See withRetry.
func (auth WristbandAuth) getUserInfo(accessToken string) (UserInfoResponse, error) {
	userInfoEndpoint := fmt.Sprintf("https://%s", auth.UserInfoEndpoint())

	return withRetry(func() (UserInfoResponse, error) {
		req, err := http.NewRequest(http.MethodGet, userInfoEndpoint, nil)
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
			return UserInfoResponse{}, &APIError{
				Operation:  "userinfo request",
				StatusCode: resp.StatusCode,
				Body:       string(body),
			}
		}

		var userInfo UserInfoResponse
		if err := json.Unmarshal(body, &userInfo); err != nil {
			return UserInfoResponse{}, err
		}

		return userInfo, nil
	})
}
