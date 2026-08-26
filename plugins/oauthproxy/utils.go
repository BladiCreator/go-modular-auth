package oauthproxy

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// StripTrailingSlash removes trailing slashes from a URL string.
func StripTrailingSlash(u string) string {
	return strings.TrimRight(u, "/")
}

// ResolveCurrentURL resolves the base URL of the current deployment environment.
// It checks in order: Config.CurrentURL, vendor environment variables, and HTTP request headers.
func ResolveCurrentURL(r *http.Request, cfg Config) (*url.URL, error) {
	if cfg.CurrentURL != "" {
		u, err := url.Parse(StripTrailingSlash(cfg.CurrentURL))
		if err == nil && u.Scheme != "" && u.Host != "" {
			return u, nil
		}
	}

	// Vendor environment variables fallback
	envVars := []string{
		"VERCEL_URL",
		"NETLIFY_URL",
		"RENDER_EXTERNAL_URL",
		"CF_PAGES_URL",
	}

	for _, env := range envVars {
		if val := os.Getenv(env); val != "" {
			if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
				val = "https://" + val
			}
			u, err := url.Parse(StripTrailingSlash(val))
			if err == nil && u.Scheme != "" && u.Host != "" {
				return u, nil
			}
		}
	}

	// Request header inspection fallback
	if r != nil {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}

		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}

		if host != "" {
			u, err := url.Parse(fmt.Sprintf("%s://%s", scheme, host))
			if err == nil && u.Host != "" {
				return u, nil
			}
		}
	}

	return nil, fmt.Errorf("oauthproxy: unable to resolve current environment URL")
}

// CheckSkipProxy determines if the proxy handling should be bypassed for a request.
func CheckSkipProxy(r *http.Request, cfg Config) bool {
	if r != nil && cfg.SkipProxyHeader != "" {
		if strings.EqualFold(r.Header.Get(cfg.SkipProxyHeader), "true") || r.Header.Get(cfg.SkipProxyHeader) == "1" {
			return true
		}
	}

	if cfg.ProductionURL == "" {
		return true
	}

	prodURL, err := url.Parse(StripTrailingSlash(cfg.ProductionURL))
	if err != nil {
		return false
	}

	if r != nil {
		currentURL, err := ResolveCurrentURL(r, cfg)
		if err == nil && strings.EqualFold(currentURL.Host, prodURL.Host) {
			return true
		}
	}

	return false
}
