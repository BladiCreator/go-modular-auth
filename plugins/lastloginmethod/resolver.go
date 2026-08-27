package lastloginmethod

import (
	"context"
	"net/http"
	"strings"
)

// ResolveMethod inspects the current request (Path, Query, Params), custom route mappings, and custom resolvers
// to infer the authentication method used.
func ResolveMethod(ctx context.Context, r *http.Request, cfg Config) (string, bool) {
	if cfg.CustomResolver != nil {
		if method, ok := cfg.CustomResolver(ctx, r); ok && method != "" {
			return method, true
		}
	}

	if r == nil || r.URL == nil {
		return "", false
	}

	path := strings.ToLower(r.URL.Path)

	// 1. Check custom route mappings configured in Config
	if len(cfg.CustomRoutes) > 0 {
		// First pass: exact match
		for pattern, method := range cfg.CustomRoutes {
			patternLower := strings.ToLower(pattern)
			if path == patternLower {
				return method, true
			}
		}
		// Second pass: substring/prefix match
		for pattern, method := range cfg.CustomRoutes {
			patternLower := strings.ToLower(pattern)
			if strings.Contains(path, patternLower) {
				return method, true
			}
		}
	}

	// 2. Return false if default routes are disabled
	if cfg.DisableDefaultRoutes {
		return "", false
	}

	// 3. Built-in default route heuristics
	// OAuth2 / Generic OAuth / OIDC callbacks: /callback/:id, /oauth2/callback/:providerId, /oauth/callback/:provider
	if strings.Contains(path, "/callback/") || strings.Contains(path, "/oauth2/callback") || strings.Contains(path, "/oauth/callback") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if (part == "callback" || part == "oauth2" || part == "oauth") && i+1 < len(parts) {
				nextPart := parts[i+1]
				if nextPart != "" && nextPart != "callback" {
					return nextPart, true
				}
			}
		}
		// Fallback to query param "provider" if path parameter is not found
		if provider := r.URL.Query().Get("provider"); provider != "" {
			return strings.ToLower(provider), true
		}
		return "oauth", true
	}

	// Email/Password
	if strings.Contains(path, "/sign-in/email") || strings.Contains(path, "/sign-up/email") {
		return "email", true
	}

	// Username
	if strings.Contains(path, "/sign-in/username") || strings.Contains(path, "/sign-up/username") {
		return "username", true
	}

	// Phone Number
	if strings.Contains(path, "/phone-number") || strings.Contains(path, "/sign-in/phone") {
		return "phone-number", true
	}

	// Passkey
	if strings.Contains(path, "/passkey") {
		return "passkey", true
	}

	// Magic Link
	if strings.Contains(path, "/magic-link") {
		return "magic-link", true
	}

	// SIWE (Sign-In with Ethereum)
	if strings.Contains(path, "/siwe") {
		return "siwe", true
	}

	// Email OTP
	if strings.Contains(path, "/email-otp") {
		return "email-otp", true
	}

	return "", false
}
