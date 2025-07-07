package goauth

import (
	"fmt"
	"net/url"
)

// LogoutURL builds the logout URL for redirecting to Wristband
func (auth WristbandAuth) LogoutURL(queryValues QueryValueResolver) string {
	baseURL := auth.Domains.TenantedHost(queryValues)
	if baseURL == "" {
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

	return baseURL + DefaultLogoutEndpoint + "?" + params.Encode()
}
