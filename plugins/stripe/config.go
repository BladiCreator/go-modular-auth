package stripe

// Config holds the configuration settings for the Stripe plugin module.
type Config struct {
	// APIKey is the secret Stripe API key (e.g. sk_test_... or sk_live_...).
	APIKey string

	// WebhookSecret is the secret used to verify webhook signatures (whsec_...).
	WebhookSecret string

	// AutoCreateCustomerOnSignUp automatically provisions a Stripe Customer when a new user registers.
	AutoCreateCustomerOnSignUp bool

	// AutoCreateCustomerOnOrgCreation automatically provisions a Stripe Customer when a new organization is created.
	AutoCreateCustomerOnOrgCreation bool
}

// Option configures a Stripe Config.
type Option func(*Config)

// WithAPIKey sets the Stripe API secret key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithWebhookSecret sets the Stripe webhook signature verification secret.
func WithWebhookSecret(secret string) Option {
	return func(c *Config) {
		c.WebhookSecret = secret
	}
}

// WithAutoCreateCustomerOnSignUp controls whether customers are automatically provisioned on user registration.
func WithAutoCreateCustomerOnSignUp(enabled bool) Option {
	return func(c *Config) {
		c.AutoCreateCustomerOnSignUp = enabled
	}
}

// WithAutoCreateCustomerOnOrgCreation controls whether customers are automatically provisioned on organization creation.
func WithAutoCreateCustomerOnOrgCreation(enabled bool) Option {
	return func(c *Config) {
		c.AutoCreateCustomerOnOrgCreation = enabled
	}
}

func defaultConfig() Config {
	return Config{
		AutoCreateCustomerOnSignUp:      true,
		AutoCreateCustomerOnOrgCreation: false,
	}
}
