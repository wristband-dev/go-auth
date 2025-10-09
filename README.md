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
- **🏢 Multi-Tenant Architecture**: Built-in support for multi-tenant applications with custom domains
- **🍪 Secure Session Management**: Encrypted cookie-based session storage with automatic token refresh
- **🛡️ Security First**: Secure defaults with CSRF protection, encrypted cookies, and token validation
- **🚀 Easy Integration**: Simple middleware-based integration with standard `net/http`
- **⚡ Token Management**: Automatic access token refresh and secure token storage
### 2) Set Up Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies.

The SDK provides a session manager interface that you need to implement:

```go
type SessionManager interface {
    StoreSession(ctx context.Context, w http.ResponseWriter, r *http.Request, session *goauth.Session) error
    GetSession(ctx context.Context, r *http.Request) (*goauth.Session, error)
    ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error
}

// Example implementation using encrypted cookies
type CookieSessionManager struct {
    encryptor *cookies.CookieEncryptor
}

func (csm *CookieSessionManager) StoreSession(ctx context.Context, w http.ResponseWriter, r *http.Request, session *goauth.Session) error {
    encryptedData := csm.encryptor.Encrypt(session)
    cookie := &http.Cookie{
        Name:     "session",
        Value:    encryptedData,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }
    http.SetCookie(w, cookie)
    return nil
}

func (csm *CookieSessionManager) GetSession(ctx context.Context, r *http.Request) (*goauth.Session, error) {
    cookie, err := r.Cookie("session")
    if err != nil {
        return nil, err
    }

    var session goauth.Session
    err = csm.encryptor.Decrypt(cookie.Value, &session)
    if err != nil {
        return nil, err
    }

    return &session, nil
}

func (csm *CookieSessionManager) ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
    cookie := &http.Cookie{
        Name:     "session",
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   -1,
    }
    http.SetCookie(w, cookie)
    return nil
}
```

<br/>

<br/>

### 3) Add Auth Endpoints

There are <ins>three core API endpoints</ins> your Go server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to your HTTP handlers.

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```go
// Login Endpoint - Route path can be whatever you prefer
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // Get the config resolver
    configResolver := wristbandAuth.GetConfigResolver()
    if configResolver == nil {
        http.Error(w, "Config resolver not available", http.StatusInternalServerError)
        return
    }

    // Get login URL (will fetch from Wristband if auto-configured)
    loginURL, err := configResolver.GetLoginURL()
    if err != nil {
        http.Error(w, "Failed to get login URL", http.StatusInternalServerError)
        return
    }

    // Add tenant domain if using subdomains
    if strings.Contains(loginURL, "{tenant_domain}") {
        // Extract tenant from subdomain or query parameter
        tenant := extractTenantFromRequest(r)
        loginURL = strings.Replace(loginURL, "{tenant_domain}", tenant, 1)
    }

    http.Redirect(w, r, loginURL, http.StatusFound)
}

func extractTenantFromRequest(r *http.Request) string {
    // Implementation depends on your multi-tenant strategy
    // Could be from subdomain, query parameter, etc.
    return "default-tenant"
}
```

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```go
func callbackHandler(w http.ResponseWriter, r *http.Request) {
    // Handle the callback
    session, err := wristbandAuth.HandleCallback(r)
    if err != nil {
        http.Error(w, "Authentication failed", http.StatusUnauthorized)
        return
    }

    // Store session using your session manager
    err = sessionManager.StoreSession(r.Context(), w, r, session)
    if err != nil {
        http.Error(w, "Failed to store session", http.StatusInternalServerError)
        return
    }

    // Redirect to application
    redirectURL := session.ReturnURL
    if redirectURL == "" {
        redirectURL = "/dashboard"
    }
    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    // Get current session
    session, err := sessionManager.GetSession(r.Context(), r)
    if err != nil {
        // No session to logout, redirect to home
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    // Clear session
    err = sessionManager.ClearSession(r.Context(), w, r)
    if err != nil {
        log.Printf("Failed to clear session: %v", err)
    }

    // Get config resolver
    configResolver := wristbandAuth.GetConfigResolver()
    if configResolver == nil {
        http.Error(w, "Config resolver not available", http.StatusInternalServerError)
        return
    }

    // Get logout URL (will fetch from Wristband if auto-configured)
    logoutURL, err := configResolver.GetLogoutURL(r)
    if err != nil {
        http.Error(w, "Failed to get logout URL", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, logoutURL, http.StatusFound)
}
```

<br/>### 4) Guard Your Protected APIs and Handle Token Refresh

Create middleware to protect your APIs and handle token refresh:

```go
// Middleware that ensures there is an authenticated user session and JWTs are not expired.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Get session from your session manager
        session, err := sessionManager.GetSession(r.Context(), r)
        if err != nil || session == nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Check if token is expired and refresh if necessary
        if session.ExpiresAt.Before(time.Now()) {
            // Get config resolver
            configResolver := wristbandAuth.GetConfigResolver()
            if configResolver != nil {
                // Refresh token
                newTokenData, err := wristbandAuth.RefreshToken(session.RefreshToken)
                if err != nil {
                    http.Error(w, "Unauthorized", http.StatusUnauthorized)
                    return
                }

                // Update session
                session.AccessToken = newTokenData.AccessToken
                session.RefreshToken = newTokenData.RefreshToken
                session.ExpiresAt = time.Now().Add(time.Duration(newTokenData.ExpiresIn) * time.Second)

                // Store updated session
                err = sessionManager.StoreSession(r.Context(), w, r, session)
                if err != nil {
                    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Add session to request context
        ctx := context.WithValue(r.Context(), "session", session)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

// Use middleware to protect routes
http.Handle("/api/protected", authMiddleware(protectedHandler))
```

### 5) Pass Your Access Token to Downstream APIs

If you need to call Wristband APIs or protect your downstream APIs:

```go
func apiCallHandler(w http.ResponseWriter, r *http.Request) {
    // Get session from context
    session := r.Context().Value("session").(*goauth.Session)
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

<br/>// Create auth with options
wristbandAuth, err := goauth.NewWristbandAuth(
    authConfig,
    goauth.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
    goauth.WithLogoutRedirectURL("/goodbye"),
)
```

## Wristband Auth Configuration Options

The `WristbandAuthConfig` struct provides comprehensive configuration options for the SDK:

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
// Configure Wristband authentication with ConfigResolver
authConfig := &goauth.AuthConfig{
    ClientID:                        "your-client-id",
    ClientSecret:                    "your-client-secret",
    WristbandApplicationVanityDomain: "your-app.wristband.dev",
    AutoConfigureEnabled:            true, // Enable auto-configuration
    Scopes:                         []string{"openid", "offline_access", "email"},
    TokenExpirationBuffer:          120, // 2 minutes
}

// Create Wristband auth instance with ConfigResolver
wristbandAuth, err := goauth.NewWristbandAuth(goauth.WristbandAuthConfig{
    Client:     authConfig.Client(),
    Domains:    goauth.AppDomains{WristbandDomain: authConfig.WristbandApplicationVanityDomain},
    AuthConfig: authConfig,
})
if err != nil {
    log.Fatal("Failed to create Wristband auth:", err)
}

// Get the ConfigResolver
configResolver := wristbandAuth.GetConfigResolver()
if configResolver != nil {
    // Get dynamic configuration values
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
