package goauth

import (
	"fmt"
	"net/url"
)

// LogoutURL builds the logout URL for redirecting to Wristband
func (auth WristbandAuth) LogoutURL(req HTTPRequest) string {
	baseURL := auth.Domains.TenantedHost(req)
	if baseURL == "" {
		if auth.logoutRedirectURI != "" {
			return auth.logoutRedirectURI
		}
		return fmt.Sprintf("https://%s/login?client_id=%s", auth.Domains.WristbandDomain, auth.Client.ClientID)
	}

	params := url.Values{}
	params.Set("client_id", auth.Client.ClientID)

	if auth.logoutRedirectURI != "" {
		params.Set("redirect_url", auth.logoutRedirectURI)
	}
	if auth.logoutStateParameter != "" {
		params.Set("state", auth.logoutStateParameter)
	}

	return baseURL + DefaultLogoutEndpoint + "?" + params.Encode()
}
