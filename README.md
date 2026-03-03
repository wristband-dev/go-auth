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

Enterprise-ready authentication for multi-tenant [Go applications](https://golang.org) using OAuth 2.1 and OpenID Connect standards.

<br>

## Overview

This SDK provides complete authentication integration with Wristband, including:

- **Login flow** - Redirect to Wristband and handle OAuth callbacks
- **Session management** - Flexible session storage with pluggable session manager interface
- **Token handling** - Automatic access token refresh
- **Logout flow** - Token revocation and session cleanup
- **Multi-tenancy** - Support for tenant subdomains and custom domains

Learn more about Wristband's authentication patterns:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

> **💡 Learn by Example**
>
> Want to see the SDK in action? Check out our [Go demo application](#wristband-multi-tenant-go-demo-app). The demo showcases a lightweight integration with the SDK.

<br>

---

<br>

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the SDK](#1-initialize-the-sdk)
  - [2) Set Up Session Storage](#2-set-up-session-storage)
  - [3) Set Up Auth Middleware](#2-set-up-auth-middleware)
  - [4) Add Auth Endpoints](#4-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Session Endpoint](#session-endpoint)
    - [Mapping Auth Endpoints](#mapping-auth-endpoints)
    - [Token Endpoint (Optional)](#token-endpoint-optional)
  - [5) Protect Your API Routes](#5-protect-your-api-routes)
  - [6) Use Your Access Token with APIs](#6-use-your-access-token-with-apis)
- [Auth Configuration Options](#auth-configuration-options)
  - [AuthConfig](#authconfig)
  - [Configuration with ConfigResolver](#configuration-with-configresolver)
  - [Cookie Configuration](#cookie-configuration)
- [Auth API](#auth-api)
  - [Login()](#login)
  - [Callback()](#callback)
  - [Logout()](#logout)
  - [RefreshTokenIfExpired()](#refreshtokenifexpired)
- [Related Wristband SDKs](#related-wristband-sdks)
- [Wristband Multi-Tenant Go Demo App](#wristband-multi-tenant-go-demo-app)
- [Questions](#questions)

<br/>

---

<br/>

## Requirements

> **⚡ Try Our Go Quickstart!**
>
> For the fastest way to get started with Go authentication, follow our [Quick Start Guide](https://docs.wristband.dev/docs/auth-quick-start). It walks you through setting up a working Go app with Wristband authentication in minutes. Refer back to this README for comprehensive documentation and advanced usage patterns.

Before installing, ensure you have:

- [Go](https://golang.org/doc/install) >= 1.24

<br>

## Installation

Add the `go-auth` package to your project:

```bash
go get github.com/wristband-dev/go-auth
```

<br>

## Usage

### 1) Initialize the SDK

First, create an instance of `WristbandAuth` in your Go application. Then, you can use this instance across your project.

```go
// main.go

package main

import (
    "log"
    "net/http"
    "time"

    goauth "github.com/wristband-dev/go-auth"
)

func main() {
    // Create the authentication configuration
    authConfig := &goauth.AuthConfig{
        ClientID:                         "your-client-id",
        ClientSecret:                     "your-client-secret",
        WristbandApplicationVanityDomain: "your-app.wristband.dev",
    }

    // Create the Wristband auth instance
    wristbandAuth, err := authConfig.WristbandAuth(
        // Optional: You can also supply your own HTTP client
        goauth.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
    )
    if err != nil {
        log.Fatal("Failed to create Wristband auth:", err)
    }
}
```

<br>

### 2) Set Up Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend encrypted cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies.

This guide shows an example of a lightweight implementation of a SessionManager using [github.com/gorilla/sessions](github.com/gorilla/sessions) that you can use in your own project.

#### Implement the Session Manager

The SDK defines a `SessionManager` interface that you need to implement. The session data is typically stored in an encrypted cookie, and on subsequent requests, the middleware decrypts the cookie and restores the session state. It defines three methods that your implementation must provide:

```go
type SessionManager interface {
    StoreSession(w http.ResponseWriter, r *http.Request, session *goauth.Session) error
    GetSession(r *http.Request) (*goauth.Session, error)
    ClearSession(w http.ResponseWriter, r *http.Request) error
}
```

1. First, run the following to download the Gorilla sessions library:

```bash
go get github.com/gorilla/sessions
```

2. Then copy this implementation into your project (e.g. `session.go`):

```go
// session.go

package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
	goauth "github.com/wristband-dev/go-auth"
)

const (
	// SessionName is the name used for the session cookie
	SessionName = "session"

	// SessionKey is the key used to store auth data in the session
	SessionKey = "auth_session"
)

// GorillaSessionManager implements the goauth.SessionManager interface
// using gorilla/sessions for session management
type GorillaSessionManager struct {
	store sessions.Store
}

func NewSessionStore(secret []byte, secureCookies bool) goauth.SessionManager {
	store := sessions.NewCookieStore(secret, nil)
	store.Options.Secure = secureCookies
	store.Options.HttpOnly = true
	store.Options.SameSite = http.SameSiteLaxMode
	store.Options.MaxAge = 3600 // 1 hour
	return &GorillaSessionManager{
		store: store,
	}
}

// StoreSession implements the goauth.SessionManager interface
func (m *GorillaSessionManager) StoreSession(w http.ResponseWriter, r *http.Request, session *goauth.Session) error {
	// Get existing session or create a new one
	sess, err := m.store.Get(r, SessionName)
	if err != nil {
		// If there's an error getting the session, create a new one
		// This can happen if the session was tampered with or is invalid
		sess, err = m.store.New(r, SessionName)
		if err != nil {
			return err
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
func (m *GorillaSessionManager) GetSession(r *http.Request) (*goauth.Session, error) {
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
func (m *GorillaSessionManager) ClearSession(w http.ResponseWriter, r *http.Request) error {
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

3. After creating your `SessionManager` implementation, you'll use it to create a Wristband app instance.

```go
// main.go

package main

import (
    goauth "github.com/wristband-dev/go-auth"
)

func main() {
    authConfig := &goauth.AuthConfig{
        ClientID:                         "your-client-id",
        ClientSecret:                     "your-client-secret",
        WristbandApplicationVanityDomain: "your-app.wristband.dev",
    }
    wristbandAuth, err := authConfig.WristbandAuth()
    if err != nil {
        // Handle error
    }

    // ADD: Create session manager
    // NOTE: You'll need to provide a secure, random 32-character secret as the secret value.
    sessionManager := NewSessionStore("<your-generated-secret>", true)

    // ADD: Create the Wristband app with the session manager
    app := wristbandAuth.NewApp(sessionManager)
}
```

<br>

### 3) Set Up Auth Middleware

Create an auth middleware using the `goauth.Middlewares` type in your project (e.g. `main.go` file). Apply `app.RequireAuthentication` to any handler that should require a valid authenticated session. This middleware retrieves the session from your configured `SessionManager`, verifies that the access token is still valid (refreshing it when necessary), and stores the session in the request context for downstream handlers. If no valid session exists, the request will receive a 401 Unauthorized response or be redirected to the login URL if token refresh fails.

```go
// main.go

package main

import (
    goauth "github.com/wristband-dev/go-auth"
)

func main() {
    authConfig := &goauth.AuthConfig{
        ClientID:                         "your-client-id",
        ClientSecret:                     "your-client-secret",
        WristbandApplicationVanityDomain: "your-app.wristband.dev",
    }
    wristbandAuth, err := authConfig.WristbandAuth()
    if err != nil {
        // Handle error
    }
    sessionManager := NewSessionStore("<your-generated-secret>", true)
    app := wristbandAuth.NewApp(sessionManager)

    // ADD: Create middleware chain for protected endpoints
    authMiddlewares := goauth.Middlewares{
        app.RequireAuthentication
    }
}
```

<br>

### 4) Add Auth Endpoints

There are **four core API endpoints** your Go server should expose to facilitate authentication workflows in Wristband:

- Login Endpoint
- Callback Endpoint
- Logout Endpoint
- Session Endpoint

You'll need to add these endpoints to your Go routes. There's also one additional endpoint you can implement depending on your authentication needs:

- Token Endpoint (optional)

<br>

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```go
// Create the Wristband app with your session manager and callback URL
app := wristbandAuth.NewApp(sessionManager)

// Login Endpoint - initiates the auth request and redirects to Wristband
http.Handle("/api/auth/login", app.LoginHandler())
```

**Options**

Optional configuration can be provided using various `LoginOpt` functions. Refer to the [Login](#LoginOptions) section for more details.

<br>

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```go
// Callback Endpoint - completes auth and creates the application session
http.Handle("/api/auth/callback",
  app.CallbackHandler(
    // Replace with your own default return URL.
    goauth.WithCallbackRedirectURL("http://localhost:5173/home"),
  ),
)
```

<br>

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

```go
// Logout Endpoint - revokes refresh token, clears session, redirects to Wristband logout
http.Handle("/api/auth/logout", app.LogoutHandler())
```

**Options**

Optional configuration can be provided using various `LogoutOption` functions. Refer to the [Logout API](#LogoutConfig) section for more details.

<br>

#### Session Endpoint

> [!NOTE]
> This endpoint is required for Wristband frontend SDKs to function. For more details, see the [Wristband Session Management documentation](https://docs.wristband.dev/docs/session-management-backend-server).

Wristband frontend SDKs require a Session Endpoint in your backend to verify authentication status and retrieve session metadata. Create a protected session endpoint that uses `app.SessionHandler()` to return the session response format expected by Wristband's frontend SDKs. The response model will always have a `UserId` and a `TenantId` in it. You can include any additional data for your frontend by customizing the `Metadata` parameter (optional), which requires JSON-serializable values. **The response must not be cached**.

> **⚠️ Important:**
> Make sure to protect this endpoint by using the auth middleware!

```go
// Session Endpoint - returns session data to the frontend
http.Handle(
    "/api/auth/session",
    authMiddlewares.Apply(app.SessionHandler())
)
```

The Session Endpoint returns a `SessionEndpointResponse` to your frontend:

```json
{
  "tenantId": "tenant_abc123",
  "userId": "user_xyz789",
  "metadata": {
    "foo": "bar",
    // Any other optional data you provide...
  }
}
```

<br>

#### Mapping Auth Endpoints

After implementing the core auth endpoints, make sure to include them in your Go application `main.go` file.

```go
// main.go

package main

import (
    goauth "github.com/wristband-dev/go-auth"
)

func main() {
    authConfig := &goauth.AuthConfig{
        ClientID:                         "your-client-id",
        ClientSecret:                     "your-client-secret",
        WristbandApplicationVanityDomain: "your-app.wristband.dev",
    }
    wristbandAuth, err := authConfig.WristbandAuth()
    if err != nil {
        // Handle error
    }
    sessionManager := NewSessionStore("<your-generated-secret>", true)
    app := wristbandAuth.NewApp(sessionManager)
    authMiddlewares := goauth.Middlewares{
        app.RequireAuthentication
    }

    // ADD: Map auth endpoints
    http.Handle("/api/auth/login", app.LoginHandler())
    http.Handle(
        "/api/auth/callback",
        app.CallbackHandler(
            goauth.WithCallbackRedirectURL("<default_return_url>")
        )
    )
    http.Handle("/api/auth/logout", app.LogoutHandler())
    http.Handle(
        "/api/auth/session",
        authMiddlewares.Apply(app.SessionHandler())
    )
}
```

<br>

#### Token Endpoint (Optional)

> [!NOTE]
> This endpoint is required when your frontend needs to make authenticated API requests directly to Wristband or other protected services. For more details, see the [Wristband documentation on using access tokens from the frontend](https://docs.wristband.dev/docs/authenticating-api-requests-with-bearer-tokens#using-access-tokens-from-the-frontend).
>
> If your application doesn't need frontend access to tokens (e.g., all API calls go through your backend), you can skip this endpoint.

Some applications require the frontend to make direct API calls to Wristband or other protected services using the user's access token. The Token Endpoint provides a secure way for your frontend to retrieve the current access token and its expiration time without exposing it in the session cookie or in browser storage.

Create a protected token endpoint that uses `app.TokenHandler()` to return the token data expected by Wristband's frontend SDKs. **The response must not be cached**.

> **⚠️ Important:**
> Make sure to protect this endpoint by using the auth middleware!

```go
// Token Endpoint - returns token data to the frontend
http.Handle(
    "/api/auth/token",
    authMiddlewares.Apply(app.TokenHandler())
)
```

The Token Endpoint returns a `TokenEndpointResponse` to your frontend:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

Your frontend can then use the `accessToken` in the Authorization header when making API requests:

```typescript
const tokenResponse = await fetch('/api/auth/token');
const { accessToken } = await tokenResponse.json();

// Use token to call Wristband API
const userResponse = await fetch('https://<your-wristband-app-vanity_domain>/api/v1/users/123', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});
```

<br>

### 5) Protect Your API Routes

To protect an endpoint from unauthenticated access, apply the auth middleware as shown below:

```go
// Protected endpoint handler
protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "This is a protected route"}`))
})

// Apply middleware to the registered protected endpoint
http.Handle("/api/protected", authMiddlewares.Apply(protectedHandler))
```

Now, if somebody tries to call this API without a valid session, a `401 Unauthorized` response will be returned.

<br>

### 6) Use Your Access Token with APIs

> [!NOTE]
> This section is only applicable if you need to call Wristband APIs or protect your own backend services with Wristband tokens.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```bash
Authorization: Bearer <access_token_value>
```

When using auth middleware, the session is automatically added to the request context. You can access it using `goauth.SessionFromContext` in order to get the access token:

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

#### Using Access Tokens from the Frontend

For scenarios where your frontend needs to make direct API calls with the user's access token, use the [Token Endpoint](#token-endpoint-optional) to securely retrieve the current access token.

<br>

---

<br>

## Auth Configuration Options

### AuthConfig

The `AuthConfig` struct provides comprehensive configuration options for the SDK:

| Field                            | Type     | Required | Default                                 | Description                                                                                                                                                                                                                    |
|----------------------------------|----------|----------|-----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ClientID                         | string   | Yes      | -                                       | The client ID for the application.                                                                                                                                                                                             |
| ClientSecret                     | string   | Yes      | -                                       | The client secret for the application.                                                                                                                                                                                         |
| WristbandApplicationVanityDomain | string   | Yes      | -                                       | The vanity domain of the Wristband application.                                                                                                                                                                                |
| AutoConfigureEnabled             | bool     | No       | `true`                                  | Tells the SDK to automatically set some configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. |
| LoginStateSecret                 | string   | No       | ClientSecret                            | A secret (32 or more characters in length) used for encryption and decryption of login state cookies. For enhanced security, it is recommended to provide a value that is unique from the client secret.                       |
| LoginURL                         | string   | No       | Auto-configured                         | The URL for initiating the login request. Required when auto-configure is disabled.                                                                                                                                            |
| RedirectURI                      | string   | No       | Auto-configured                         | The redirect URI for callback after authentication. Required when auto-configure is disabled.                                                                                                                                  |
| CustomApplicationLoginPageURL    | string   | No       | Auto-configured                         | The custom application login (tenant discovery) page URL if you are self-hosting the application login/tenant discovery UI.                                                                                                    |
| DangerouslyDisableSecureCookies  | bool     | No       | `false`                                 | If set to true, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development.                                                                                |
| IsApplicationCustomDomainActive  | *bool    | No       | Auto-configured                         | Indicates whether an application-level custom domain is active in your Wristband application.                                                                                                                                  |
| ParseTenantFromRootDomain        | string   | No       | Auto-configured                         | The root domain for your application from which to parse out the tenant domain name. Indicates whether tenant subdomains are used for authentication.                                                                          |
| Scopes                           | []string | No       | `["openid", "offline_access", "email"]` | The scopes required for authentication.                                                                                                                                                                                        |
| TokenExpirationBuffer            | int      | No       | `60`                                    | The buffer time (in seconds) to subtract from the access token's expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls.             |

<br>

### Configuration with ConfigResolver

The SDK supports both manual configuration and autoconfiguration via the ConfigResolver:

```go
// Configure Wristband authentication with autoconfiguration enabled
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

**Available Options**

The `WristbandAuth()` method accepts the following optional parameters:

| Option                                                    | Description                                         |
|-----------------------------------------------------------|-----------------------------------------------------|
| `WithHTTPClient(client *http.Client)`                     | Uses a custom HTTP client for API requests.         |
| `WithCookieEncryption(cookieEncryption CookieEncryption)` | Provides a custom cookie encryption implementation. |

<br>

### Cookie Configuration

Configure cookie options for session storage:

```go
app := wristbandAuth.NewApp(sessionManager,
    goauth.WithCookieOptions(goauth.CookieOptions{
        Domain: ".yourapp.com",
        Path:   "/",
        MaxAge: 86400, // 24 hours
        // DangerouslyDisableSecureCookies: true, // Only for development
    }),
)
```

<br>

## Auth API

This section covers integration with the SDK for custom HTTP handlers instead of the provided ones. It can also be used when working with a web framework.

### Common Interfaces

There are some abstractions around http requests and responses to enable integration with various web frameworks. Implementations are provided for the standard library which are used in the Wristband provided `http.Handler` implementations.

They are abstracted away using the `HTTPContext` interface. This interface is used to:
- Read URI information using the 
- Listing request cookie names and retrieving a request cookie via the `cookies.CookieRequest` interface.
- Writing response cookies.

### HandleLogin

`WristbandAuth.HandleLogin` initiates the authentication flow by generating an authorization URL and storing login state in a cookie. Refer to [LoginHandler](handlers.go) for an example.

**Parameters**

| Parameter | Type         | Required | Description                                |
|-----------|--------------|----------|--------------------------------------------|
| httpCtx   | HTTPContext  | Yes      | The HTTP request/response context          |
| options   | *LoginOption | Yes      | Optional configuration for the login flow. |

**Returns**

| Type   | Description                                                                   |
|--------|-------------------------------------------------------------------------------|
| string | The authorization url to redirect to with the necessary query parameters set. |
| error  | Any error that occurred during login flow.                                    |

#### LoginOptions

These are all optional configurations to be used for building the authorize request URL. The `LoginOpt` interface provides the ability to set these configurations. 

| Option                          | Description                                                                                                                                      |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `WithCustomState`               | Custom state data for the login request..                                                                                                        |
| `WithReturnURL`                 | URL to return to after authentication is completed. If a value is provided, then it takes precedence over the return_url request query parameter |
| `WithDefaultTenantCustomDomain` | Tenant custom domain for the login request if the name cannot be found in either the subdomain or the "tenant_custom_domain" query parameter.    |
| `WithDefaultTenantName`         | Tenant name for the login request if the name cannot be found in either the subdomain or the "tenant_name" query parameter                       |

Use the `NewLoginOptions` function to initialize the configuration to be provided to `HandleLogin`. 

#### Which Domains Are Used in the Authorize URL?

Wristband supports multiple tenant domain configurations, including tenant subdomains and tenant custom domains. When the Go SDK constructs the Wristband Authorize URL during `Login()`, it resolves the tenant domain using the following precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the request host: Used when `AuthConfig.ParseTenantFromRootDomain` is configured and the incoming request host contains a tenant subdomain.
3. `tenant_name` query parameter: Evaluated when tenant subdomains are not being used.
4. `WithDefaultTenantCustomDomain(domain string)` login option: Used if none of the above are present.
5. `WithDefaultTenantName(name string)` login option: Used as the final fallback.

If none of these are specified, `Login()` returns the Application-Level Login (Tenant Discovery) URL (or your configured `CustomApplicationLoginPageURL`), which your login handler should redirect the user to.

#### Tenant Name Query Param

If your application does not wish to utilize tenant subdomains, you can pass the `tenant_name` query parameter to your Login Endpoint and the SDK will use it when generating the Wristband Authorize URL.

```sh
GET https://yourapp.io/auth/login?tenant_name=customer01
```

Your `AuthConfig` might look like the following when manually configuring URLs (no tenant subdomains):

```go
authConfig := goauth.NewAuthConfig(
    "ic6saso5hzdvbnof3bwgccejxy",
    "30e9977124b13037d035be10d727806f",
    "yourapp-yourcompany.us.wristband.dev",
    goauth.WithAutoConfigureDisabled(
        "https://yourapp.io/auth/login",
        "https://yourapp.io/auth/callback",
    ),
)

wristbandAuth, err := authConfig.WristbandAuth()
if err != nil {
    // handle error
}
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your Login Endpoint. The SDK will parse the tenant subdomain from the request host when `AuthConfig.ParseTenantFromRootDomain` is configured. When using tenant subdomains, your configured `login_url` and `redirect_uri` must contain the `{tenant_name}` placeholder.

```sh
GET https://customer01.yourapp.io/auth/login
```

Your `AuthConfig` might look like the following when manually configuring URLs for tenant subdomains:

```go
authConfig := goauth.NewAuthConfig(
    "ic6saso5hzdvbnof3bwgccejxy",
    "30e9977124b13037d035be10d727806f",
    "yourapp-yourcompany.us.wristband.dev",
    goauth.WithParseTenantFromRootDomain("yourapp.io"),
    goauth.WithAutoConfigureDisabled(
        "https://{tenant_name}.yourapp.io/auth/login",
        "https://{tenant_name}.yourapp.io/auth/callback",
    ),
)

wristbandAuth, err := authConfig.WristbandAuth()
if err != nil {
    // handle error
}
```

#### Default Tenant Name

For certain use cases, it may be useful to specify a default tenant name in the event that `HandleLogin` cannot resolve a tenant name in either the request query parameters or the URL subdomain. You can specify a fallback default tenant name via `WithDefaultTenantName(...)`:

```go
http.HandleFunc("/auth/login", app.LoginHandler(
    goauth.WithDefaultTenantName("default"),
))
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that `HandleLogin` cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via `WithDefaultTenantCustomDomain(...)`:

```go
http.HandleFunc("/auth/login", app.LoginHandler(
    goauth.WithDefaultTenantCustomDomain("mytenant.com"),
))
```

The default tenant custom domain takes precedence over all other possible domain configurations when present except for the case where the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint. You can inject additional state into that cookie by setting `LoginOptions.CustomState`:

```go
http.HandleFunc("/auth/login", app.LoginHandler(goauth.WithCustomState(map[string]any{"test": "abc"}))
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `customState` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `customState` JSON of at most 1kB should be a safe ceiling.

**Example**

```go
http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
    authURL, err := wristbandAuth.Login(w, r,
        goauth.WithDefaultTenantName("default-tenant"),
    )
    if err != nil {
        http.Error(w, "Login failed", http.StatusInternalServerError)
        return
    }
    http.Redirect(w, r, authURL, http.StatusFound)
})
```

<br>

### HandleCallback

Handles the OAuth callback from Wristband, exchanges the authorization code for tokens, and retrieves user information.

**Parameters**

| Parameter | Type         | Required | Description                                |
|-----------|--------------|----------|--------------------------------------------|
| httpCtx   | HTTPContext  | Yes      | The HTTP request/response context          |

**Returns**

| Type            | Description                                         |
|-----------------|-----------------------------------------------------|
| *CallbackContext | Contains tokens, user info, and redirect URL.       |
| error           | Any error that occurred during callback processing. |

When an error is returned, use `goauth.IsRedirectError` in case the request should be redirected. If so, log the error and redirect. 

**CallbackContext Fields**

| Field              | Type             | Description                                                 |
|--------------------|------------------|-------------------------------------------------------------|
| TokenResponse      | TokenResponse    | OAuth tokens (access, refresh, ID tokens, and expiration).  |
| LoginState         | LoginState       | Login context (return URL, nonce, code verifier, state).    |
| UserInfo           | UserInfoResponse | User information from the Wristband Userinfo endpoint.      |
| TenantName         | string           | The tenant name for the authenticated user.                 |
| TenantCustomDomain | string           | Custom domain for the tenant.                               |

**Example**

```go
http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
    result, err := wristbandAuth.Callback(w, r)
    if err != nil {
		// Check for redirection.
        if redirectError, ok := goauth.IsRedirectError(err); ok {
            http.Redirect(res, req, redirectError.URL, http.StatusSeeOther)
        }
        http.Error(w, "Callback failed", http.StatusInternalServerError)
        return
    }

    // Store session and redirect
    session := &goauth.Session{
        AccessToken:  result.AccessToken,
        RefreshToken: result.RefreshToken,
        ExpiresAt:    result.ExpiresAt,
        UserId:       result.UserInfo.Sub,
        TenantId:     result.TenantId,
    }
    sessionManager.StoreSession(r.Context(), w, r, session)
    http.Redirect(w, r, result.RedirectURL, http.StatusFound)
})
```

<br>

### LogoutURL

Generates a logout URL for the Wristband logout endpoint.

**Parameters**

| Parameter | Type         | Required | Description                                 |
|-----------|--------------|----------|---------------------------------------------|
| req       | RequestURI   | Yes      | The HTTP request URI context                |
| options   | LogoutConfig | Yes      | Optional configuration for the logout flow. |

**Returns**

| Type   | Description                             |
|--------|-----------------------------------------|
| string | The logout URL to redirect the user to. |
| error  | Any error that occurred during logout.  |


#### LogoutConfig

The `LogoutConfig` can be configured using `NewLogoutConfig` and providing any desired `LogoutOption` configurations.

| Option                                  | Description                               |
|-----------------------------------------|-------------------------------------------|
| `WithRedirectURL(url string)`           | Sets the URL to redirect to after logout. |
| `WithTenantDomain(domain string)`       | Sets the tenant domain for logout.        |
| `WithTenantCustomDomain(domain string)` | Sets the tenant custom domain for logout. |

**Example**

```go
http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
    session, _ := sessionManager.GetSession(r.Context(), r)
    if session == nil {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }
	httpCtx := wristbandAuth.NewStandardHttpContext(w, r)

    logoutURL, err := wristbandAuth.LogoutURL(httpCtx, NewLogoutConfig())
    if err != nil {
        http.Error(w, "Logout failed", http.StatusInternalServerError)
        return
    }

	// Revoke token as necessary
    if session.RefreshToken != "" {
        _ = wristbandAuth.RevokeToken(session.RefreshToken, goauth.RefreshTokenType)
	}

    sessionManager.ClearSession(r.Context(), w, r)
    http.Redirect(w, r, logoutURL, http.StatusFound)
})
```

<br>

### RevokeToken

Revokes the refresh token.

**Parameters**

| Parameter | Type   | Required | Description       |
|-----------|--------|----------|-------------------|
| token     | string | Yes      | The token value   |
| tokenType | string | Yes      | The type of token |

**Returns**

| Type   | Description                                    |
|--------|------------------------------------------------|
| error  | Any error that occurred during revoke request. |

<br>

### RefreshTokenIfExpired()

Checks if the access token is expired (or about to expire based on `TokenExpirationBuffer`) and refreshes it if necessary.

**Parameters**

| Parameter    | Type   | Required | Description                                                |
|--------------|--------|----------|------------------------------------------------------------|
| refreshToken | string | Yes      | The refresh token to use for obtaining a new access token. |
| expiresAt    | int64  | Yes      | Absolute expiration time of the current access token in milliseconds since the Unix epoch. |


**Returns**

| Type           | Description                                          |
|----------------|------------------------------------------------------|
| *TokenResponse | Contains new tokens if refreshed, nil if not needed. |
| error          | Any error that occurred during token refresh.        |

**TokenResponse Fields**

| Field        | Type   | Description                                       |
|--------------|--------|---------------------------------------------------|
| AccessToken  | string | The new access token.                             |
| TokenType    | string | The token type (e.g., "Bearer").                  |
| RefreshToken | string | The new refresh token (if rotated).               |
| IDToken      | string | The ID token containing user identity claims.     |
| ExpiresIn    | int    | Token lifetime in seconds.                        |


**Example**

```go
func refreshMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, _ := sessionManager.GetSession(r.Context(), r)
        if session == nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        tokenResponse, err := wristbandAuth.RefreshTokenIfExpired(
            session.RefreshToken,
            session.ExpiresAt,
        )
        if err != nil {
            http.Error(w, "Token refresh failed", http.StatusUnauthorized)
            return
        }

        // Update session if tokens were refreshed
        if tokenResponse != nil {
            session.AccessToken = tokenResponse.AccessToken
            session.RefreshToken = tokenResponse.RefreshToken
            session.ExpiresAt = tokenResponse.ExpiresAt
            sessionManager.StoreSession(r.Context(), w, r, session)
        }

        next.ServeHTTP(w, r)
    })
}
```

<br>

---

<br>

## Related Wristband SDKs

This SDK integrates with other Wristband SDKs to provide a complete authentication solution:

**[@wristband/react-client-auth](https://github.com/wristband-dev/react-client-auth)**

For handling client-side authentication and session management in your React frontend, check out the Wristband React Client Auth SDK. It integrates seamlessly with this backend SDK by consuming the Session and Token endpoints you create. Refer to that GitHub repository for more information on frontend authentication patterns.

<br>

## Wristband Multi-Tenant Go Demo App

You can check out the [Wristband Go demo app](https://github.com/wristband-dev/go-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>

---

Made with ❤️ by the [Wristband](https://wristband.dev) team
