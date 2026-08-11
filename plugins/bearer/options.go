package bearer

// Config holds configuration parameters for the Bearer plugin.
type Config struct {
	// Secret defines the cryptographic secret key used for signing and verifying tokens via HMAC-SHA256.
	Secret string

	// RequireSignature specifies whether incoming tokens must strictly arrive pre-signed.
	// When false (default), raw unsigned tokens are signed automatically using the configured Secret.
	RequireSignature bool

	// TokenHeader specifies the HTTP header name from which to extract the bearer token (default: "Authorization").
	TokenHeader string

	// AuthTokenHeader specifies the HTTP response header name used to expose the token (default: "set-auth-token").
	AuthTokenHeader string

	// ExposeHeaders specifies whether to configure CORS Access-Control-Expose-Headers for the response header (default: true).
	ExposeHeaders bool
}

// Option defines a functional configuration option for the Bearer plugin.
type Option func(*Config)

// DefaultConfig returns the default production configuration for the Bearer plugin.
func DefaultConfig() Config {
	return Config{
		Secret:           "",
		RequireSignature: false,
		TokenHeader:      HeaderAuthorization,
		AuthTokenHeader:  HeaderSetAuthToken,
		ExposeHeaders:    true,
	}
}

// WithSecret sets the cryptographic secret key used for HMAC-SHA256 token signing and verification.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithRequireSignature configures whether the plugin strictly enforces pre-signed tokens.
func WithRequireSignature(require bool) Option {
	return func(c *Config) {
		c.RequireSignature = require
	}
}

// WithTokenHeader customizes the incoming HTTP request header name used to parse the token (default: "Authorization").
func WithTokenHeader(header string) Option {
	return func(c *Config) {
		if header != "" {
			c.TokenHeader = header
		}
	}
}

// WithAuthTokenHeader customizes the outgoing HTTP response header name where the token is exposed (default: "set-auth-token").
func WithAuthTokenHeader(header string) Option {
	return func(c *Config) {
		if header != "" {
			c.AuthTokenHeader = header
		}
	}
}

// WithExposeHeaders configures whether the output header should be published in CORS Access-Control-Expose-Headers.
func WithExposeHeaders(expose bool) Option {
	return func(c *Config) {
		c.ExposeHeaders = expose
	}
}

// WithCustomTokenHeader is an alias for WithTokenHeader.
func WithCustomTokenHeader(header string) Option {
	return WithTokenHeader(header)
}

// WithCustomAuthTokenHeader is an alias for WithAuthTokenHeader.
func WithCustomAuthTokenHeader(header string) Option {
	return WithAuthTokenHeader(header)
}
