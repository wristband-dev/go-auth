package go_auth

import (
	"fmt"
	"net/url"
)

// LogoutURL builds the logout URL for redirecting to Wristband
func (auth WristbandAuth) LogoutURL(queryValues QueryValueResolver) string {
	baseUrl := auth.Domains.TenantedHost(queryValues)
	if baseUrl == "" {
		if auth.logoutRedirectURI != "" {
			return auth.logoutRedirectURI
		}
		return fmt.Sprintf("https://%s/login?client_id=%s", auth.Domains.WristbandDomain, auth.Client.ClientID)
	}

	params := url.Values{}
	params.Set("client_id", auth.Client.ClientID)

	if auth.logoutRedirectURI != "" {
		params.Set("post_logout_redirect_uri", auth.logoutRedirectURI)
	}

	return baseUrl + DefaultLogoutEndpoint + "?" + params.Encode()
}
