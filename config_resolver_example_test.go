package goauth

import (
	"fmt"
	"log"
)

// ExampleConfigResolver demonstrates how to use the new ConfigResolver functionality
func ExampleConfigResolver() {
	// Create an AuthConfig with the new pattern
	authConfig := &AuthConfig{
		ClientID:                         "your-client-id",
		ClientSecret:                     "your-client-secret",
		WristbandApplicationVanityDomain: "your-app.wristband.dev",
		AutoConfigureEnabled:             true, // Enable auto-configuration
		// LoginURL and RedirectURI will be auto-configured from Wristband
	}

	// Create a ConfigResolver
	configResolver, err := NewConfigResolver(authConfig)
	if err != nil {
		log.Fatalf("Failed to create config resolver: %v", err)
	}

	// Get static configuration
	fmt.Printf("Client ID: %s\n", configResolver.GetClientID())
	fmt.Printf("Scopes: %v\n", configResolver.GetScopes())

	// Get dynamic configuration (will fetch from Wristband if needed)
	loginURL, err := configResolver.GetLoginURL()
	if err != nil {
		log.Printf("Failed to get login URL: %v", err)
	} else {
		fmt.Printf("Login URL: %s\n", loginURL)
	}

	redirectURI, err := configResolver.GetRedirectURI()
	if err != nil {
		log.Printf("Failed to get redirect URI: %v", err)
	} else {
		fmt.Printf("Redirect URI: %s\n", redirectURI)
	}

	// Preload SDK configuration for eager loading
	err = configResolver.PreloadSdkConfig()
	if err != nil {
		log.Printf("Failed to preload SDK config: %v", err)
	}
}

// WristbandAuthWithConfigResolver demonstrates using ConfigResolver with WristbandAuth
func WristbandAuthWithConfigResolver() {
	// Create AuthConfig
	authConfig := &AuthConfig{
		ClientID:                         "your-client-id",
		ClientSecret:                     "your-client-secret",
		WristbandApplicationVanityDomain: "your-app.wristband.dev",
		AutoConfigureEnabled:             true,
		Scopes:                           []string{"openid", "offline_access", "email", "profile"},
		TokenExpirationBuffer:            120, // 2 minutes
	}

	// Create WristbandAuth with AuthConfig
	wristbandAuth, err := NewWristbandAuth(WristbandAuthConfig{
		Client: authConfig.Client(),
		Domains: AppDomains{
			WristbandDomain: authConfig.WristbandApplicationVanityDomain,
		},
		AuthConfig: authConfig,
	})

	if err != nil {
		log.Fatalf("Failed to create WristbandAuth: %v", err)
	}

	// Access ConfigResolver
	configResolver := wristbandAuth.GetConfigResolver()
	if configResolver != nil {
		fmt.Printf("Using ConfigResolver with auto-configure: %v\n", configResolver.GetAutoConfigureEnabled())

		// Get configuration values
		clientID := wristbandAuth.GetClientID()
		fmt.Printf("Client ID: %s\n", clientID)

		scopes := wristbandAuth.GetScopes()
		fmt.Printf("Scopes: %v\n", scopes)
	}
}
