package stripe


// Config holds operational settings and options for the Stripe plugin.
type Config struct {
	// StripeAPIKey is the secret API key used to initialize the Stripe API client (e.g. "sk_test_...").
	StripeAPIKey string

	// WebhookSecret is the secret used to cryptographically verify incoming Stripe-Signature headers.
	WebhookSecret string

	// CreateCustomerOnSignUp automatically creates a Stripe Customer record when a new user registers.
	CreateCustomerOnSignUp bool

	// Subscription contains configuration options for subscription billing.
	Subscription *SubscriptionOptions

	// Organization contains configuration options for organization seat-based billing.
	Organization *OrganizationOptions
}

// SubscriptionOptions holds detailed configuration rules for plans, authorization, and lifecycle callbacks.
type SubscriptionOptions struct {
	Plans                      []StripePlan
	PlansFunc                  PlansFunc
	RequireEmailVerification   bool
	AuthorizeReference         AuthorizeReferenceFunc
	OnSubscriptionCompleted    SubscriptionCallbackFunc
	OnSubscriptionCreated      SubscriptionCallbackFunc
	OnSubscriptionUpdated      SubscriptionCallbackFunc
	OnSubscriptionCanceled     SubscriptionCallbackFunc
	OnSubscriptionDeleted      SubscriptionCallbackFunc
	OnInvoicePaymentSucceeded InvoiceCallbackFunc
	OnInvoicePaymentFailed     InvoiceCallbackFunc
}

// OrganizationOptions holds options for organization-level seat-based billing.
type OrganizationOptions struct {
	Enabled     bool
	SeatPriceID string
}

// Option represents a functional configuration option for configuring the Stripe plugin.
type Option func(*Config)

// DefaultConfig returns recommended production default settings for the Stripe plugin.
func DefaultConfig() Config {
	return Config{
		CreateCustomerOnSignUp: true,
		Subscription: &SubscriptionOptions{
			Plans: []StripePlan{},
		},
		Organization: &OrganizationOptions{
			Enabled: false,
		},
	}
}

// WithStripeAPIKey sets the Stripe secret API key.
func WithStripeAPIKey(key string) Option {
	return func(c *Config) {
		c.StripeAPIKey = key
	}
}

// WithWebhookSecret sets the webhook secret key for verifying Stripe-Signature HTTP headers.
func WithWebhookSecret(secret string) Option {
	return func(c *Config) {
		c.WebhookSecret = secret
	}
}

// WithCreateCustomerOnSignUp toggles automatic creation of a Stripe customer record during sign-up.
func WithCreateCustomerOnSignUp(enable bool) Option {
	return func(c *Config) {
		c.CreateCustomerOnSignUp = enable
	}
}

// WithPlans defines static subscription plans available in the application.
func WithPlans(plans ...StripePlan) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.Plans = plans
	}
}

// WithPlansFunc sets a dynamic function for resolving available subscription plans.
func WithPlansFunc(fn PlansFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.PlansFunc = fn
	}
}

// WithAuthorizeReference configures a callback to authorize referenceId access during subscription actions.
func WithAuthorizeReference(fn AuthorizeReferenceFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.AuthorizeReference = fn
	}
}

// WithOnSubscriptionCreated registers a callback triggered when a subscription is created.
func WithOnSubscriptionCreated(fn SubscriptionCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnSubscriptionCreated = fn
	}
}

// WithOnSubscriptionUpdated registers a callback triggered when a subscription state updates.
func WithOnSubscriptionUpdated(fn SubscriptionCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnSubscriptionUpdated = fn
	}
}

// WithOnSubscriptionDeleted registers a callback triggered when a subscription is canceled or deleted.
func WithOnSubscriptionDeleted(fn SubscriptionCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnSubscriptionDeleted = fn
	}
}

// WithOnInvoicePaymentSucceeded registers a callback triggered when an invoice payment succeeds.
func WithOnInvoicePaymentSucceeded(fn InvoiceCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnInvoicePaymentSucceeded = fn
	}
}

// WithOnInvoicePaymentFailed registers a callback triggered when an invoice payment fails.
func WithOnInvoicePaymentFailed(fn InvoiceCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnInvoicePaymentFailed = fn
	}
}

// WithSeatPriceID configures organization seat-based billing with a specific Stripe Seat Price ID.
func WithSeatPriceID(seatPriceID string) Option {
	return func(c *Config) {
		if c.Organization == nil {
			c.Organization = &OrganizationOptions{}
		}
		c.Organization.Enabled = true
		c.Organization.SeatPriceID = seatPriceID
	}
}
