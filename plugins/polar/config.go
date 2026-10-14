package polar

// Config holds the configuration settings for the Polar plugin module.
type Config struct {
	// AccessToken is the Polar API bearer token (e.g. polar_at_...).
	AccessToken string

	// WebhookSecret is the secret used to verify webhook signatures.
	WebhookSecret string

	// ServerURL is the Polar API server URL (e.g. "https://api.polar.sh" or "https://sandbox-api.polar.sh").
	ServerURL string

	// AutoCreateCustomerOnSignUp automatically provisions a Polar Customer when a new user registers.
	AutoCreateCustomerOnSignUp bool

	// AutoCreateCustomerOnOrgCreation automatically provisions a Polar Customer when a new organization is created.
	AutoCreateCustomerOnOrgCreation bool
}

// Option configures a Polar Config.
type Option func(*Config)

// WithAccessToken sets the Polar API access token.
func WithAccessToken(token string) Option {
	return func(c *Config) {
		c.AccessToken = token
	}
}

// WithWebhookSecret sets the Polar webhook signature verification secret.
func WithWebhookSecret(secret string) Option {
	return func(c *Config) {
		c.WebhookSecret = secret
	}
}

// WithServerURL sets the Polar API base server URL.
func WithServerURL(url string) Option {
	return func(c *Config) {
		c.ServerURL = url
	}
}

// WithAutoCreateCustomerOnSignUp controls automatic provisioning on user registration.
func WithAutoCreateCustomerOnSignUp(enabled bool) Option {
	return func(c *Config) {
		c.AutoCreateCustomerOnSignUp = enabled
	}
}

// WithAutoCreateCustomerOnOrgCreation controls automatic provisioning on organization creation.
func WithAutoCreateCustomerOnOrgCreation(enabled bool) Option {
	return func(c *Config) {
		c.AutoCreateCustomerOnOrgCreation = enabled
	}
}

func defaultConfig() Config {
	return Config{
		ServerURL:                       "https://api.polar.sh",
		AutoCreateCustomerOnSignUp:      true,
		AutoCreateCustomerOnOrgCreation: false,
	}
}
