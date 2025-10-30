package goauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type LogoutConfig struct {
	RedirectURL        string
	State              string
	TenantCustomDomain string
	TenantName         string
}

type LogoutOption interface {
	apply(*LogoutConfig)
}
type LogoutOptionFunc func(*LogoutConfig)

func (f LogoutOptionFunc) apply(options *LogoutConfig) {
	f(options)
}

// WithRedirectURL sets the redirect URL used for the logout flow
func WithRedirectURL(redirectURL string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.RedirectURL = redirectURL
	})
}

// WithState is used to set the state query parameter in the logout
func WithState(state string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.State = state
	})
}

// LogoutUrl builds the logout URL for redirecting to Wristband
func (auth WristbandAuth) LogoutUrl(req HTTPRequest, config LogoutConfig) (string, error) {
	if len(config.State) > 512 {
		return "", fmt.Errorf("the [state] logout config cannot exceed 512 characters")
	}

	params := url.Values{}
	params.Set("client_id", auth.Client.ClientID)

	if config.RedirectURL != "" {
		params.Set("redirect_url", config.RedirectURL)
	}
	if config.State != "" {
		params.Set("state", config.State)
	}

	host, err := auth.logoutHost(req, config)
	if err != nil {
		if errors.Is(err, NoTenantNameError) {
			if config.RedirectURL != "" {
				return config.RedirectURL, nil
			}
			if customLogin, err := auth.configResolver.GetCustomApplicationLoginPageURL(); err == nil {
				if customLogin != "" {
					return customLogin, nil
				}
				return fmt.Sprintf("https://%s/login?client_id=%s", auth.configResolver.WristbandApplicationVanityDomain, auth.Client.ClientID), nil
			} else {
				return "", err
			}
		}
	}

	return fmt.Sprintf("https://%s/api/v1/logout?%s", host, params.Encode()), nil
}

var NoTenantNameError = fmt.Errorf("no tenant name resolvable")

func (auth WristbandAuth) logoutHost(req HTTPRequest, options LogoutConfig) (string, error) {
	if options.TenantCustomDomain != "" {
		return options.TenantCustomDomain, nil
	}
	if options.TenantName != "" {
		return strings.Join([]string{options.TenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}
	if customTenantName, ok := auth.RequestCustomTenantName(req); ok {
		return customTenantName, nil
	}
	if tenantName, err := auth.RequestTenantName(req); err == nil && tenantName != "" {
		return strings.Join([]string{tenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	} else {
		// TODO Log
	}
	return "", NoTenantNameError
}
