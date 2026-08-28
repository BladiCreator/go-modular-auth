package polar

import (
	"context"
	"strings"
)

// AuthorizeReferenceData holds parameters passed to the AuthorizeReference callback function.
type AuthorizeReferenceData struct {
	ReferenceID string
	UserID      string
	Action      string
}

// AuthorizeReferenceFunc is a callback that determines whether a user is authorized to perform an action on a referenceId.
type AuthorizeReferenceFunc func(ctx context.Context, data AuthorizeReferenceData) (bool, error)

// PlansFunc is a dynamic callback function for resolving available Polar plans.
type PlansFunc func(ctx context.Context) ([]PolarPlan, error)

// SubscriptionCallbackFunc is a callback invoked when a subscription event occurs.
type SubscriptionCallbackFunc func(ctx context.Context, sub *Subscription) error

// CustomerStateCallbackFunc is a callback invoked when a customer's state changes.
type CustomerStateCallbackFunc func(ctx context.Context, state *CustomerState) error

// OrderCallbackFunc is a callback invoked when an order is paid.
type OrderCallbackFunc func(ctx context.Context, order *CustomerOrder) error

// BenefitCallbackFunc is a callback invoked when a benefit is granted or revoked.
type BenefitCallbackFunc func(ctx context.Context, benefit *CustomerBenefit) error

// Config holds operational settings and options for the Polar plugin.
type Config struct {
	// AccessToken is the Polar Bearer access token used to authenticate API requests.
	AccessToken string

	// WebhookSecret is the secret used to cryptographically verify incoming Polar webhook signatures.
	WebhookSecret string

	// Server environment URL or environment identifier (e.g. "sandbox", "production").
	Server string

	// CreateCustomerOnSignUp automatically creates a Polar Customer record when a new user registers.
	CreateCustomerOnSignUp bool

	// Subscription contains configuration options for subscription billing.
	Subscription *SubscriptionOptions

	// Portal contains options for Customer Portal sessions.
	Portal *PortalOptions

	// Usage contains options for usage event ingestion.
	Usage *UsageOptions

	// Organization contains configuration options for organization seat-based billing.
	Organization *OrganizationOptions
}

// SubscriptionOptions holds detailed configuration rules for plans, authorization, and lifecycle callbacks.
type SubscriptionOptions struct {
	Plans                    []PolarPlan
	PlansFunc                PlansFunc
	RequireEmailVerification bool
	AuthorizeReference       AuthorizeReferenceFunc
	OnSubscriptionCreated    SubscriptionCallbackFunc
	OnSubscriptionUpdated    SubscriptionCallbackFunc
	OnSubscriptionCanceled   SubscriptionCallbackFunc
	OnCustomerStateChanged   CustomerStateCallbackFunc
	OnOrderPaid              OrderCallbackFunc
	OnBenefitGranted         BenefitCallbackFunc
	OnBenefitRevoked         BenefitCallbackFunc
}

// PortalOptions holds settings for Customer Portal generation.
type PortalOptions struct {
	ReturnURL          string
	AuthorizeReference AuthorizeReferenceFunc
}

// UsageOptions holds settings for usage reporting.
type UsageOptions struct {
	DefaultEvents []string
}

// OrganizationOptions holds options for organization-level seat-based billing.
type OrganizationOptions struct {
	Enabled       bool
	SeatProductID string
}

// Option represents a functional configuration option for configuring the Polar plugin.
type Option func(*Config)

// DefaultConfig returns recommended production default settings for the Polar plugin.
func DefaultConfig() Config {
	return Config{
		CreateCustomerOnSignUp: true,
		Server:                 "production",
		Subscription: &SubscriptionOptions{
			Plans: []PolarPlan{},
		},
		Portal: &PortalOptions{},
		Usage:  &UsageOptions{},
		Organization: &OrganizationOptions{
			Enabled: false,
		},
	}
}

// WithAccessToken sets the Polar API access token.
func WithAccessToken(token string) Option {
	return func(c *Config) {
		c.AccessToken = token
	}
}

// WithWebhookSecret sets the webhook secret key for verifying Polar webhook signatures.
func WithWebhookSecret(secret string) Option {
	return func(c *Config) {
		c.WebhookSecret = secret
	}
}

// WithServer sets the server environment (e.g. "sandbox" or "production").
func WithServer(server string) Option {
	return func(c *Config) {
		c.Server = server
	}
}

// WithCreateCustomerOnSignUp toggles automatic creation of a Polar customer record during sign-up.
func WithCreateCustomerOnSignUp(enable bool) Option {
	return func(c *Config) {
		c.CreateCustomerOnSignUp = enable
	}
}

// WithPlans defines static subscription plans available in the application.
func WithPlans(plans ...PolarPlan) Option {
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

// WithOnSubscriptionCreated sets a callback triggered when a subscription is created.
func WithOnSubscriptionCreated(fn SubscriptionCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnSubscriptionCreated = fn
	}
}

// WithOnSubscriptionUpdated sets a callback triggered when a subscription is updated.
func WithOnSubscriptionUpdated(fn SubscriptionCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnSubscriptionUpdated = fn
	}
}

// WithOnSubscriptionCanceled sets a callback triggered when a subscription is canceled.
func WithOnSubscriptionCanceled(fn SubscriptionCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnSubscriptionCanceled = fn
	}
}

// WithOnCustomerStateChanged sets a callback triggered when customer state changes.
func WithOnCustomerStateChanged(fn CustomerStateCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnCustomerStateChanged = fn
	}
}

// WithOnOrderPaid sets a callback triggered when an order is paid.
func WithOnOrderPaid(fn OrderCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnOrderPaid = fn
	}
}

// WithOnBenefitGranted sets a callback triggered when a benefit is granted.
func WithOnBenefitGranted(fn BenefitCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnBenefitGranted = fn
	}
}

// WithOnBenefitRevoked sets a callback triggered when a benefit is revoked.
func WithOnBenefitRevoked(fn BenefitCallbackFunc) Option {
	return func(c *Config) {
		if c.Subscription == nil {
			c.Subscription = &SubscriptionOptions{}
		}
		c.Subscription.OnBenefitRevoked = fn
	}
}

// GetPlanByID searches for a configured plan matching planID by ID, product ID, or price ID.
func GetPlanByID(cfg Config, planID string) (PolarPlan, bool) {
	if cfg.Subscription == nil {
		return PolarPlan{}, false
	}
	for _, p := range cfg.Subscription.Plans {
		if strings.EqualFold(p.ID, planID) || strings.EqualFold(p.ProductID, planID) || strings.EqualFold(p.PriceID, planID) {
			return p, true
		}
	}
	return PolarPlan{}, false
}
