package goauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// LogoutConfig is the configuration for the logout flow.
type LogoutConfig struct {
	RedirectURL        string
	State              string
	TenantCustomDomain string
	TenantName         string
}

// LogoutOption is an option for the logout flow.
type LogoutOption interface {
	apply(*LogoutConfig)
}

// LogoutOptionFunc is a function that implements the LogoutOption interface.
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

// WithTenantCustomDomain sets the tenant custom domain.
func WithTenantCustomDomain(tenantDomain string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.TenantCustomDomain = tenantDomain
	})
}

// WithTenantName sets the tenant name.
func WithTenantName(tenantName string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.TenantName = tenantName
	})
}

// LogoutURL builds the logout URL for redirecting to Wristband
func (auth WristbandAuth) LogoutURL(req HTTPRequest, config LogoutConfig) (string, error) {
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
		if errors.Is(err, ErrTenantNameNotFound) {
			if config.RedirectURL != "" {
				return config.RedirectURL, nil
			}
			if customLogin, err := auth.configResolver.GetCustomApplicationLoginPageURL(); err == nil {
				if customLogin != "" {
					return customLogin, nil
				}
				return fmt.Sprintf("https://%s/login?client_id=%s", auth.configResolver.WristbandApplicationVanityDomain, auth.Client.ClientID), nil
			}
			return "", err
		}
	}

	return fmt.Sprintf("https://%s/api/v1/logout?%s", host, params.Encode()), nil
}

// ErrTenantNameNotFound is returned when no tenant name can be resolved.
var ErrTenantNameNotFound = fmt.Errorf("no tenant name resolvable")

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
	}
	return "", ErrTenantNameNotFound
}
