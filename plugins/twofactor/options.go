package twofactor

// Config contains configuration settings for the TwoFactor plugin.
type Config struct {
	Issuer string
}

// Option defines a functional option for configuring the TwoFactor plugin.
type Option func(*Config)

// WithIssuer sets the issuer name embedded in the generated TOTP URI (e.g. "My App").
func WithIssuer(issuer string) Option {
	return func(c *Config) { c.Issuer = issuer }
}