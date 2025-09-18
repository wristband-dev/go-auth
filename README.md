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

The Wristband Go SDK enables seamless integration of your Go applications with the Wristband authentication platform, providing robust user authentication, session management, and multi-tenant support for modern web applications.

## Features

- **🔐 OAuth 2.0 & OIDC Compliance**: Full support for OAuth 2.0 authorization code flow with PKCE
- **🏢 Multi-Tenant Architecture**: Built-in support for multi-tenant applications with custom domains
- **🍪 Secure Session Management**: Encrypted cookie-based session storage with automatic token refresh
- **🛡️ Security First**: Secure defaults with CSRF protection, encrypted cookies, and token validation
- **🚀 Easy Integration**: Simple middleware-based integration with standard `net/http`
- **⚡ Token Management**: Automatic access token refresh and secure token storage
- **🎨 Customizable**: Flexible configuration options for domains, endpoints, and session handling

## Requirements

This SDK is designed to work for Go 1.21+.

<br/>

## Installation

Install the SDK using Go modules:

```bash
go get github.com/wristband-dev/go-auth
```

## Quick Start

### 1. Basic Setup

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/wristband-dev/go-auth"
)

func main() {
    // Configure Wristband authentication
    authConfig := goauth.WristbandAuthConfig{
        Client: goauth.NewConfidentialClient(
            "your-client-id",
            "your-client-secret",
        ),
        Domains: goauth.AppDomains{
            WristbandDomain: "your-app.wristband.dev",
            RootDomain:      "yourapp.com",
        },
    }
    
    // Create Wristband auth instance
    wristbandAuth, err := goauth.NewWristbandAuth(authConfig)
    if err != nil {
        log.Fatal("Failed to create Wristband auth:", err)
    }
    
    // Configure the application
    app := goauth.NewApp(wristbandAuth, goauth.AppInput{
        LoginPath:      "/api/auth/login",
        CallbackURL:    "/api/auth/callback",
        SessionManager: &MySessionManager{}, // Implement your session manager
    })
    
    // Set up routes
    http.HandleFunc("/api/auth/login", app.LoginHandler())
    http.HandleFunc("/api/auth/callback", app.CallbackHandler())
    http.HandleFunc("/api/auth/logout", app.LogoutHandler())
    http.HandleFunc("/api/auth/session", app.SessionHandler())
    
    // Protected routes
    http.Handle("/dashboard", app.RequireAuthentication(http.HandlerFunc(dashboardHandler)))
    
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Get user session from context
    session := goauth.SessionFromContext(r.Context())
    if session != nil {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Welcome, " + session.Name + "!"))
    }
}
```

### 2. Implement Session Manager

The SDK requires a session manager implementation to handle session storage:

```go
type MySessionManager struct {
    // Your session storage implementation (Redis, database, etc.)
}

func (sm *MySessionManager) StoreSession(ctx context.Context, w http.ResponseWriter, r *http.Request, session *goauth.Session) error {
    // Store session in your preferred storage
    // Example: store in encrypted cookie, Redis, database, etc.
    return nil
}

func (sm *MySessionManager) GetSession(ctx context.Context, r *http.Request) (*goauth.Session, error) {
    // Retrieve session from your storage
    // Return nil, error if no session exists
    return nil, errors.New("no session found")
}

func (sm *MySessionManager) ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
    // Clear session from your storage
    return nil
}
```

## Configuration

### Domain Configuration

The SDK supports various domain configurations for multi-tenant applications:

```go
// Single tenant configuration
domains := goauth.AppDomains{
    WristbandDomain: "yourapp.wristband.dev",
}

// Multi-tenant with subdomain routing
domains := goauth.AppDomains{
    WristbandDomain: "yourapp.wristband.dev",
    RootDomain:      "yourapp.com",
    ParseTenantFromRootDomain: true,
}

// Multi-tenant with custom domains
domains := goauth.AppDomains{
    WristbandDomain: "yourapp.wristband.dev",
    IsApplicationCustomDomainActive: true,
    DefaultDomains: &goauth.TenantDomains{
        TenantDomain: "default-tenant",
    },
}
```

### Advanced Configuration

```go
authConfig := goauth.WristbandAuthConfig{
    Client: goauth.NewConfidentialClient(clientID, clientSecret),
    Domains: domains,
    SecretKey: []byte("your-32-byte-encryption-key-here"), // Optional: for cookie encryption
}

// Create auth with options
wristbandAuth, err := goauth.NewWristbandAuth(
    authConfig,
    goauth.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
    goauth.WithLogoutRedirectURL("/goodbye"),
)
```

## Middleware

### Authentication Middleware

Protect routes that require authentication:

```go
// Require authentication for specific routes
protectedMux := http.NewServeMux()
protectedMux.HandleFunc("/profile", profileHandler)
protectedMux.HandleFunc("/settings", settingsHandler)

// Apply authentication middleware
http.Handle("/", app.RequireAuthentication(protectedMux))
```

### Token Refresh Middleware

Automatically refresh expired tokens:

```go
// Apply token refresh middleware before authentication
http.Handle("/api/", app.RefreshTokenIfExpired(
    app.RequireAuthentication(apiMux),
))
```

### Cache Control Middleware

Prevent caching of sensitive responses:

```go
http.Handle("/api/", goauth.CacheControlMiddleware(
    app.RequireAuthentication(apiMux),
))
```

## Session Management

### Accessing User Session

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // Get session from context (available after RequireAuthentication middleware)
    session := goauth.SessionFromContext(r.Context())
    if session == nil {
        http.Error(w, "No session found", http.StatusUnauthorized)
        return
    }
    
    // Access user information
    userID := session.UserID
    tenantID := session.TenantID
    userName := session.Name
    userInfo := session.UserInfo
    
    // Use session data
    fmt.Fprintf(w, "Hello %s from tenant %s!", userName, tenantID)
}
```

### Session Structure

```go
type Session struct {
    AccessToken  string             `json:"access_token"`
    RefreshToken string             `json:"refresh_token"`
    ExpiresAt    time.Time          `json:"expires_at"`
    UserInfo     UserInfoResponse   `json:"user_info"`
    UserID       string             `json:"userID"`
    Name         string             `json:"name"`
    TenantID     string             `json:"tenantId"`
    IDPName      string             `json:"idpName"`
}
```

## Token Management

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
