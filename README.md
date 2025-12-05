<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> •
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Wristband Multi-Tenant Authentication SDK for Go

[![Go Version](https://img.shields.io/github/go-mod/go-version/wristband-dev/go-auth)](https://golang.org/doc/go1.24)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This module facilitates seamless interaction with Wristband for user authentication within multi-tenant Go applications. It follows OAuth 2.1 and OpenID standards.

Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the SDK](#1-initialize-the-sdk)
  - [2) Set Up Session Storage](#2-set-up-session-storage)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
  - [4) Guard Your Protected APIs and Handle Token Refresh](#4-guard-your-protected-apis-and-handle-token-refresh)
  - [5) Pass Your Access Token to Downstream APIs](#5-pass-your-access-token-to-downstream-apis)
- [Wristband Auth Configuration Options](#wristband-auth-configuration-options)
- [API](#api)
  - [WristbandAuth](#wristbandauth)
  - [ConfigResolver](#configresolver)
- [Questions](#questions)

<br/>


### 1) Initialize the SDK

Create a Wristband authentication client using `AuthConfig`:

```go
// Create the authentication configuration
authConfig := &goauth.AuthConfig{
    ClientID:                         "your-client-id",
    ClientSecret:                     "your-client-secret",
    WristbandApplicationVanityDomain: "your-app.wristband.dev",
    AutoConfigureEnabled:             true, // Enable auto-configuration (default)
}

// Create the Wristband auth instance
auth, err := authConfig.WristbandAuth(
    goauth.WithLogoutRedirectURL("/goodbye"),
    goauth.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
)
if err != nil {
    log.Fatal("Failed to create Wristband auth:", err)
}
```

#### Key Features:
- **🏢 Multi-Tenant Architecture**: Built-in support for multi-tenant applications with custom domains
- **🍪 Secure Session Management**: Encrypted cookie-based session storage with automatic token refresh
- **🚀 Easy Integration**: Simple middleware-based integration with standard `net/http`
- **⚡ Token Management**: Automatic access token refresh and secure token storage
### 2) Set Up Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies.

The SDK provides a session manager interface that you need to implement.

```go
type SessionManager interface {
    StoreSession(ctx context.Context, w http.ResponseWriter, r *http.Request, session *goauth.Session) error
    GetSession(ctx context.Context, r *http.Request) (*goauth.Session, error)
    ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error
}
```

Example implementation using `github.com/gorilla`:

```go
import (
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

func NewStore() goauth.SessionManager {
    store := sessions.NewCookieStore(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))
    return &GorillaSessionManager{
        store: store,
    }
}

const (
	// SessionName is the name used for the session cookie
	SessionName = "session"

	// SessionKey is the key used to store auth data in the session
	SessionKey = "auth_session"
)

// GorillaSessionManager implements the wristbandauth.SessionManager interface
// using gorilla/sessions for session management
type GorillaSessionManager struct {
	store sessions.Store
}

// StoreSession implements the goauth.SessionManager interface
func (m *GorillaSessionManager) StoreSession(_ context.Context, w http.ResponseWriter, r *http.Request, session *goauth.Session) error {
	// Get existing session or create a new one
	sess, err := m.store.Get(r, SessionName)
	if err != nil {
		// If there's an error getting the session, create a new one
		// This can happen if the session was tampered with or is invalid
		sess = sessions.NewSession(m.store, SessionName)
		sess.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 30, // 30 days
			HttpOnly: true,
			Secure:   false, // Make sure this is true in production
			SameSite: http.SameSiteLaxMode,
		}
	}

	// Serialize the session to JSON
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return err
	}

	// Store the serialized session in the session store
	sess.Values[SessionKey] = string(sessionJSON)

	// Save the session
	return sess.Save(r, w)
}

// GetSession implements the goauth.SessionManager interface
func (m *GorillaSessionManager) GetSession(_ context.Context, r *http.Request) (*goauth.Session, error) {
	// Get existing session
	sess, err := m.store.Get(r, SessionName)
	if err != nil {
		return nil, err
	}

	// Check if the session contains auth data
	sessionJSON, ok := sess.Values[SessionKey]
	if !ok {
		return nil, errors.New("no auth session found")
	}

	// Parse the serialized session
	var authSession goauth.Session
	err = json.Unmarshal([]byte(sessionJSON.(string)), &authSession)
	if err != nil {
		return nil, err
	}

	return &authSession, nil
}

// ClearSession implements the goauth.SessionManager interface
func (m *GorillaSessionManager) ClearSession(_ context.Context, w http.ResponseWriter, r *http.Request) error {
	// Get existing session
	sess, err := m.store.Get(r, SessionName)
	if err != nil {
		// If we can't get the session, that's fine - we wanted to clear it anyway
		return nil
	}

	// Remove the auth data from the session
	delete(sess.Values, SessionKey)

	// Set session to expire
	sess.Options.MaxAge = -1

	// Save the session
	return sess.Save(r, w)
}
```

<br/>

<br/>

### 3) Add Auth Endpoints

There are <ins>three core API endpoints</ins> your Go server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to your HTTP handlers.

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```go
// Create the Wristband app with your session manager and callback URL
app := goauth.NewApp(wristbandAuth, goauth.AppInput{
    CallbackURL:    "https://your-app.com/callback",
    SessionManager: sessionManager,
})

// Login Endpoint - initiates the auth request and redirects to Wristband
http.HandleFunc("/login", app.LoginHandler(
    // Optional: set default tenant behavior for login
    goauth.WithDefaultTenantName("default-tenant"),
))
```

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```go
// Callback Endpoint - completes auth and creates the application session
http.HandleFunc("/callback", app.CallbackHandler())
```

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

```go
// Logout Endpoint - revokes refresh token, clears session, redirects to Wristband logout
http.HandleFunc("/logout", app.LogoutHandler(
    goauth.WithRedirectURL("/goodbye"),
))
```

<br/>### 4) Guard Your Protected APIs and Handle Token Refresh

Create middleware to protect your APIs and handle token refresh:

```go
// Use built-in middleware to require auth and auto-refresh access tokens
protected := app.RequireAuthentication(app.RefreshTokenIfExpired(http.HandlerFunc(protectedHandler)))
http.Handle("/api/protected", protected)
```

### 5) Pass Your Access Token to Downstream APIs

If you need to call Wristband APIs or protect your downstream APIs:

```go
func apiCallHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve session set by RequireAuthentication
    session := goauth.SessionFromContext(r.Context())
    if session == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Make API call with access token
    req, err := http.NewRequest("GET", "https://api.yourapp.com/data", nil)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    req.Header.Set("Authorization", "Bearer "+session.AccessToken)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    // Process response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```


## Wristband Auth Configuration Options

The `AuthConfig` struct provides comprehensive configuration options for the SDK:

```go
type AuthConfig struct {
    // AutoConfigureEnabled tells the SDK to automatically set some configuration values by
    // calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations
    // will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default.
    // When disabled, if manual configurations are not provided, then an error will be thrown.
    AutoConfigureEnabled bool

    // ClientID is the client ID for the application
    ClientID string

    // ClientSecret is the client secret for the application
    ClientSecret string

    // LoginStateSecret is a secret (32 or more characters in length) used for encryption and decryption
    // of login state cookies. If not provided, it will default to using the client secret.
    // For enhanced security, it is recommended to provide a value that is unique from the client secret.
    LoginStateSecret string

    // LoginURL is the URL for initiating the login request. This field is auto-configurable.
    // Required when auto-configure is disabled.
    LoginURL string

    // RedirectURI is the redirect URI for callback after authentication. This field is auto-configurable.
    // Required when auto-configure is disabled.
    RedirectURI string

    // WristbandApplicationVanityDomain is the vanity domain of the Wristband application
    WristbandApplicationVanityDomain string

    // CustomApplicationLoginPageURL is the custom application login (tenant discovery) page URL
    // if you are self-hosting the application login/tenant discovery UI. This field is auto-configurable.
    CustomApplicationLoginPageURL string

    // DangerouslyDisableSecureCookies if set to true, the "Secure" attribute will not be
    // included in any cookie settings. This should only be done when testing in local development.
    DangerouslyDisableSecureCookies bool

    // IsApplicationCustomDomainActive indicates whether an application-level custom domain
    // is active in your Wristband application. This field is auto-configurable.
    IsApplicationCustomDomainActive *bool

    // ParseTenantFromRootDomain is the root domain for your application from which to parse
    // out the tenant domain name. Indicates whether tenant subdomains are used for authentication.
    // This field is auto-configurable.
    ParseTenantFromRootDomain string

    // Scopes are the scopes required for authentication. Defaults to ["openid", "offline_access", "email"]
    Scopes []string

    // TokenExpirationBuffer is the buffer time (in seconds) to subtract from the access token's expiration time.
    // This causes the token to be treated as expired before its actual expiration, helping to avoid token
    // expiration during API calls. Defaults to 60 seconds.
    TokenExpirationBuffer int
}
```

### Configuration with ConfigResolver

The SDK supports both manual configuration and auto-configuration via the ConfigResolver:

```go
// Configure Wristband authentication with auto-configuration enabled
authConfig := &goauth.AuthConfig{
    ClientID:                         "your-client-id",
    ClientSecret:                     "your-client-secret",
    WristbandApplicationVanityDomain: "your-app.wristband.dev",
    AutoConfigureEnabled:             true, // Enable auto-configuration
    Scopes:                           []string{"openid", "offline_access", "email"},
    TokenExpirationBuffer:            120, // 2 minutes
}

// Create Wristband auth instance (with optional custom HTTP client)
wristbandAuth, err := authConfig.WristbandAuth(
    goauth.WithHTTPClient(customHTTPClient),
)
if err != nil {
    log.Fatal("Failed to create Wristband auth:", err)
}
```

### Available Options

The `WristbandAuth()` method accepts the following optional parameters:

- **`WithHTTPClient(client *http.Client)`**: Uses a custom HTTP client for API requests
- **`WithCookieEncryption(cookieEncryption CookieEncryption)`**: Provides a custom cookie encryption implementation

```go
if configResolver != nil {
    // Get dynamic configuration values
    loginURL, err := configResolver.GetLoginURL()
    if err != nil {
        log.Printf("Failed to get login URL: %v", err)
    } else {
        fmt.Printf("Login URL: %s\n", loginURL)
    }

    redirectURI := configResolver.GetRedirectURI()
    fmt.Printf("Redirect URI: %s\n", redirectURI)
}
```

<br/>

### Manual Token Operations

```go
// Refresh an access token
tokenResponse, err := wristbandAuth.RefreshAccessToken(refreshToken)
if err != nil {
    log.Printf("Token refresh failed: %v", err)
}

// Revoke a token
err = wristbandAuth.RevokeToken(accessToken, "access_token")
if err != nil {
    log.Printf("Token revocation failed: %v", err)
}
```

### Client Credentials Flow

For machine-to-machine authentication:

```go
tokenReq := goauth.NewClientCredentialsTokenRequest(
    goauth.NewConfidentialClient(clientID, clientSecret),
    "https://your-app.wristband.dev/api/v1/oauth2/token",
)

tokenResponse, err := tokenReq.Do(http.DefaultClient)
if err != nil {
    log.Printf("Client credentials token request failed: %v", err)
}
```

## Cookie Configuration

Configure cookie options for session storage:

```go
app := goauth.NewApp(wristbandAuth, appInput, 
    goauth.WithCookieOptions(goauth.CookieOptions{
        Domain: ".yourapp.com",
        Path:   "/",
        MaxAge: 86400, // 24 hours
        // DangerouslyDisableSecureCookies: true, // Only for development
    }),
)
```

## Security Considerations

- **Always use HTTPS in production** - The SDK sets secure cookies by default
- **Implement proper session storage** - Use Redis, database, or other secure storage for production
- **Validate redirect URLs** - Ensure callback URLs are properly validated
- **Use strong encryption keys** - Provide a secure 32-byte key for cookie encryption
- **Implement proper CSRF protection** - The SDK includes built-in state parameter validation
- **Monitor token expiration** - Use the refresh middleware for automatic token renewal

## Testing

The SDK includes comprehensive test coverage. Run tests with:

```bash
go test ./...
```

For integration testing, set up test environment variables:

```bash
export WRISTBAND_CLIENT_ID="test-client-id"
export WRISTBAND_CLIENT_SECRET="test-client-secret"
export WRISTBAND_DOMAIN="test-app.wristband.dev"
go test -integration ./...
```

## Troubleshooting

### Common Issues

**"Invalid domains configuration"**
- Ensure `WristbandDomain` is properly set
- Verify `RootDomain` is set when using `ParseTenantFromRootDomain`

**"Secret key must be exactly 32 bytes"**
- Provide a 32-byte encryption key or leave empty for auto-generation

**"Token request failed"**
- Verify client credentials are correct
- Check network connectivity to Wristband endpoints
- Ensure proper OAuth 2.0 flow implementation

**Session not persisting**
- Implement proper session manager
- Check cookie configuration and domain settings
- Verify HTTPS is used in production

## API Reference

For complete API documentation, visit [pkg.go.dev](https://pkg.go.dev/github.com/wristband-dev/go-auth) or generate local documentation:

```bash
go doc -all github.com/wristband-dev/go-auth
```

## Support

- **Documentation**: [https://docs.wristband.dev](https://docs.wristband.dev)
- **Community**: [Wristband Community Forum](https://community.wristband.dev)
- **Email**: [support@wristband.dev](mailto:support@wristband.dev)
- **Issues**: [GitHub Issues](https://github.com/wristband-dev/go-auth/issues)

## Related SDKs

Wristband provides SDKs for multiple frameworks:

- [Next.js SDK](https://github.com/wristband-dev/nextjs-auth)
- [FastAPI SDK](https://github.com/wristband-dev/fastapi-auth)
- [Django SDK](https://github.com/wristband-dev/django-auth)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by the [Wristband](https://wristband.dev) team
