package goauth

import (
	"net/url"
	"strings"
)

// leadingTenantPlaceholderPrefixes are the only valid positions for the {tenant_name} placeholder in a URL:
// the leftmost part of the hostname.
var leadingTenantPlaceholderPrefixes = []string{
	"https://" + TenantNameToken + ".",
	"http://" + TenantNameToken + ".",
}

// deriveFallbackLoginURL derives the fallback login URL from a login URL that uses the {tenant_name} placeholder.
//
// The placeholder must be the leftmost part of the hostname, e.g. https://{tenant_name}.example.com/auth/login.
// The fallback login URL is the login URL with the placeholder removed, e.g. https://example.com/auth/login.
// When the login URL has no placeholder, the result is an empty string.
func deriveFallbackLoginURL(loginURL string) string {
	if !strings.Contains(loginURL, TenantNameToken) {
		return ""
	}
	return strings.Replace(loginURL, TenantNameToken+".", "", 1)
}

// deriveTenantRootDomain derives the root domain used for parsing tenant subdomains from a login URL that uses
// the {tenant_name} placeholder. The root domain is the hostname with the placeholder removed, without any port,
// e.g. example.com. When the login URL has no placeholder, the result is an empty string.
func deriveTenantRootDomain(loginURL string) string {
	fallbackLoginURL := deriveFallbackLoginURL(loginURL)
	if fallbackLoginURL == "" {
		return ""
	}
	parsed, err := url.Parse(fallbackLoginURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// isTenantPlaceholderPositionValid checks that a URL containing the {tenant_name} placeholder has it exactly once,
// as the leftmost part of the hostname. URLs without the placeholder are always considered valid.
func isTenantPlaceholderPositionValid(rawURL string) bool {
	if !strings.Contains(rawURL, TenantNameToken) {
		return true
	}
	for _, prefix := range leadingTenantPlaceholderPrefixes {
		if strings.HasPrefix(rawURL, prefix) {
			// Removing the leading placeholder should leave no other {tenant_name} anywhere in the URL.
			return !strings.Contains(strings.Replace(rawURL, TenantNameToken+".", "", 1), TenantNameToken)
		}
	}
	return false
}

// normalizeURLLikeBrowser applies the same clean-up a browser does before navigating to a URL: it strips
// leading and trailing C0 control characters and spaces, removes ASCII tabs and newlines, and treats
// backslashes as forward slashes. This makes tricks like "/\evil.com" or "/\t/evil.com" resolve to the
// same host during validation that the browser would actually redirect to.
func normalizeURLLikeBrowser(rawURL string) string {
	trimmed := strings.TrimFunc(rawURL, func(r rune) bool {
		return r <= 0x20
	})
	cleaned := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, trimmed)
	return strings.ReplaceAll(cleaned, `\`, "/")
}

// validateReturnURL validates a user-supplied return URL to prevent open redirects. Without this, an attacker
// could craft a login link with return_url=https://evil.com so that a legitimate login ends with the user being
// sent to a site they don't control.
//
// Relative paths resolve against the current request's host. The scheme must match the request's scheme, and the
// hostname must be either the root domain (when tenant subdomains are in use) or the request's host. When
// app-level authorization requests are enabled and tenant subdomains are in use, a return URL on the bare root
// domain is rewritten to the tenant's subdomain (e.g. myapp.com -> acme.myapp.com).
//
// It returns the validated URL, or an empty string if the return URL is missing, malformed, or not allowed.
func validateReturnURL(
	returnURL, requestScheme, requestHost, tenantName string,
	applicationAuthorizationRequestsEnabled bool,
	rootDomain string,
) string {
	if returnURL == "" || tenantName == "" {
		return ""
	}

	base, err := url.Parse(requestScheme + "://" + requestHost)
	if err != nil {
		return ""
	}
	normalizedURL := normalizeURLLikeBrowser(returnURL)
	ref, err := url.Parse(normalizedURL)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)

	resolvedHostname := strings.ToLower(resolved.Hostname())
	requestHostname := strings.ToLower(base.Hostname())
	rootDomain = strings.ToLower(rootDomain)

	// Only allow redirects to the root domain or the exact host that served this request, over the same
	// scheme. Anything else is treated as untrusted and discarded. The scheme check blocks downgrades like
	// https -> http.
	if !strings.EqualFold(resolved.Scheme, requestScheme) || resolvedHostname == "" {
		return ""
	}
	if resolvedHostname != requestHostname && (rootDomain == "" || resolvedHostname != rootDomain) {
		return ""
	}

	if rootDomain != "" && applicationAuthorizationRequestsEnabled && resolvedHostname == rootDomain {
		// The return URL points at the bare root domain, but the app expects tenant subdomains. Prepend the
		// resolved tenant so the user lands on their tenant's host. Path, query, fragment, and port are preserved.
		host := tenantName + "." + resolved.Hostname()
		if port := resolved.Port(); port != "" {
			host += ":" + port
		}
		resolved.Host = host
		return resolved.String()
	}

	// Allowed host and no tenant rewrite needed. Return the URL unchanged unless normalization changed it, in
	// which case return the normalized absolute URL so the browser lands exactly where we validated.
	if normalizedURL == returnURL {
		return returnURL
	}
	return resolved.String()
}
