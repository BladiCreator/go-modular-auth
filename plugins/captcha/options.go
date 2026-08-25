package captcha

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// Provider identifies a supported captcha verification provider.
type Provider string

const (
	// ProviderCloudflareTurnstile represents Cloudflare Turnstile captcha service.
	ProviderCloudflareTurnstile Provider = "cloudflare-turnstile"

	// ProviderGoogleRecaptcha represents Google reCAPTCHA v2 / v3 service.
	ProviderGoogleRecaptcha Provider = "google-recaptcha"

	// ProviderHCaptcha represents hCaptcha verification service.
	ProviderHCaptcha Provider = "hcaptcha"

	// ProviderCaptchaFox represents CaptchaFox verification service.
	ProviderCaptchaFox Provider = "captchafox"
)

// IPExtractorFunc extracts the client's remote IP address from an incoming HTTP request.
type IPExtractorFunc func(r *http.Request) string

// DefaultIPExtractor extracts remote client IP address from request headers or RemoteAddr.
func DefaultIPExtractor(r *http.Request) string {
	if r == nil {
		return ""
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		ip := strings.TrimSpace(realIP)
		if ip != "" {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}

	return r.RemoteAddr
}

// Config structures all operational settings for the Captcha plugin.
type Config struct {
	// Provider specifies the active captcha provider (Turnstile, reCAPTCHA, hCaptcha, CaptchaFox).
	Provider Provider

	// SecretKey is the private secret key obtained from the captcha provider dashboard.
	SecretKey string

	// SiteKey is the public site key (required by hCaptcha and CaptchaFox verification endpoints).
	SiteKey string

	// Endpoints defines the list of HTTP request path URIs protected by captcha verification.
	Endpoints []string

	// ExemptEndpoints defines paths explicitly exempted from captcha verification.
	ExemptEndpoints []string

	// SiteVerifyURLOverride allows overriding the official provider siteverify URL (useful for testing or enterprise endpoints).
	SiteVerifyURLOverride string

	// MinScore sets minimum score threshold for Google reCAPTCHA v3 (default: 0.5).
	MinScore float64

	// ExpectedAction validates expected action parameter for Turnstile or reCAPTCHA v3 responses.
	ExpectedAction string

	// AllowedHostnames restricts valid captcha tokens to specified hostnames/domains.
	AllowedHostnames []string

	// HTTPClient allows injecting custom *http.Client for outgoing verification requests.
	HTTPClient *http.Client

	// Timeout specifies maximum duration allowed for outgoing verification HTTP call (default: 10s).
	Timeout time.Duration

	// IPExtractor function to extract remote IP address from incoming requests.
	IPExtractor IPExtractorFunc
}

// DefaultConfig returns default operational configuration for the Captcha plugin.
func DefaultConfig() Config {
	endpointsCopy := make([]string, len(DefaultEndpoints))
	copy(endpointsCopy, DefaultEndpoints)

	exemptCopy := make([]string, len(DefaultExemptEndpoints))
	copy(exemptCopy, DefaultExemptEndpoints)

	return Config{
		Provider:        ProviderCloudflareTurnstile,
		Endpoints:       endpointsCopy,
		ExemptEndpoints: exemptCopy,
		MinScore:        DefaultMinScore,
		Timeout:         DefaultVerifyTimeout,
		IPExtractor:     DefaultIPExtractor,
	}
}

// Option configures functional options for the Captcha plugin.
type Option func(*Config)

// WithProvider sets the captcha provider.
func WithProvider(p Provider) Option {
	return func(c *Config) {
		c.Provider = p
	}
}

// WithSecretKey sets the provider secret key.
func WithSecretKey(key string) Option {
	return func(c *Config) {
		c.SecretKey = key
	}
}

// WithSiteKey sets the provider site key.
func WithSiteKey(key string) Option {
	return func(c *Config) {
		c.SiteKey = key
	}
}

// WithEndpoints configures protected endpoint URIs.
func WithEndpoints(endpoints []string) Option {
	return func(c *Config) {
		if endpoints != nil {
			c.Endpoints = endpoints
		}
	}
}

// WithExemptEndpoints configures exempted endpoint URIs.
func WithExemptEndpoints(exempt []string) Option {
	return func(c *Config) {
		if exempt != nil {
			c.ExemptEndpoints = exempt
		}
	}
}

// WithSiteVerifyURLOverride overrides provider default siteverify URL.
func WithSiteVerifyURLOverride(urlStr string) Option {
	return func(c *Config) {
		c.SiteVerifyURLOverride = urlStr
	}
}

// WithMinScore sets minimum score threshold for Google reCAPTCHA v3.
func WithMinScore(score float64) Option {
	return func(c *Config) {
		c.MinScore = score
	}
}

// WithExpectedAction sets expected action string for Turnstile or reCAPTCHA v3.
func WithExpectedAction(action string) Option {
	return func(c *Config) {
		c.ExpectedAction = action
	}
}

// WithAllowedHostnames sets allowed hostnames list.
func WithAllowedHostnames(hostnames []string) Option {
	return func(c *Config) {
		c.AllowedHostnames = hostnames
	}
}

// WithHTTPClient configures custom HTTP client for verification calls.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		c.HTTPClient = client
	}
}

// WithTimeout sets maximum timeout for verification HTTP call.
func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.Timeout = d
		}
	}
}

// WithIPExtractor configures custom client IP extractor function.
func WithIPExtractor(fn IPExtractorFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.IPExtractor = fn
		}
	}
}
