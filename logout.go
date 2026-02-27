package goauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// LogoutConfig is the configuration for the logout flow.
type LogoutConfig struct {
	redirectURL        string
	state              string
	tenantCustomDomain string
	tenantName         string
}

// NewLogoutConfig constructs the LogoutConfig.
func NewLogoutConfig(opts ...LogoutOption) LogoutConfig {
	cfg := LogoutConfig{}
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	return cfg
}

// LogoutOption is an option for the logout flow.
type LogoutOption interface {
	apply(*LogoutConfig)
}

// LogoutOptionFunc is a function that implements the LogoutOption interface.
type LogoutOptionFunc func(*LogoutConfig)

func (f LogoutOptionFunc) apply(config *LogoutConfig) {
	f(config)
}

// WithRedirectURL sets the redirect URL used for the logout flow
func WithRedirectURL(redirectURL string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.redirectURL = redirectURL
	})
}

// WithState is used to set the state query parameter in the logout
func WithState(state string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.state = state
	})
}

// WithTenantCustomDomain sets the tenant custom domain.
func WithTenantCustomDomain(tenantDomain string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.tenantCustomDomain = tenantDomain
	})
}

// WithTenantName sets the tenant name.
func WithTenantName(tenantName string) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		config.tenantName = tenantName
	})
}

// WithSession sets the TenantName and TenantCustomDomain using the Session's values if the current config's values are empty.
func WithSession(session Session) LogoutOption {
	return LogoutOptionFunc(func(config *LogoutConfig) {
		if config.tenantCustomDomain == "" {
			config.tenantCustomDomain = session.TenantCustomDomain
		}
		if config.tenantName == "" {
			config.tenantName = session.TenantName
		}
	})
}

// LogoutURL builds the logout URL for redirecting to Wristband
func (auth WristbandAuth) LogoutURL(req RequestURI, config LogoutConfig) (string, error) {
	if len(config.state) > 512 {
		return "", fmt.Errorf("the [state] logout config cannot exceed 512 characters")
	}

	params := url.Values{}
	params.Set("client_id", auth.Client.ClientID)

	if config.redirectURL != "" {
		params.Set("redirect_url", config.redirectURL)
	}
	if config.state != "" {
		params.Set("state", config.state)
	}

	host, err := auth.logoutHost(req, config)
	if err != nil {
		if errors.Is(err, ErrTenantNameNotFound) {
			if config.redirectURL != "" {
				return config.redirectURL, nil
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

func (auth WristbandAuth) logoutHost(req RequestURI, options LogoutConfig) (string, error) {
	if options.tenantCustomDomain != "" {
		return options.tenantCustomDomain, nil
	}
	if options.tenantName != "" {
		return strings.Join([]string{options.tenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}
	if customTenantName, ok := auth.RequestCustomTenantName(req); ok {
		return customTenantName, nil
	}
	if tenantName, err := auth.RequestTenantName(req); err == nil && tenantName != "" {
		return strings.Join([]string{tenantName, auth.configResolver.WristbandApplicationVanityDomain}, auth.separator()), nil
	}
	return "", ErrTenantNameNotFound
}
