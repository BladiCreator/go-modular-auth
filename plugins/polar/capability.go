package polar

import "context"

// Polar defines the typed capability interface exported by the Polar plugin module.
// Applications retrieve this via auth.Get[polar.Polar](engine).
type Polar interface {
	// GetCustomer retrieves the Polar customer mapped to the target reference (user or organization).
	GetCustomer(ctx context.Context, target TargetReference) (*Customer, error)

	// CreateCustomer explicitly provisions a customer in Polar and saves the local mapping.
	CreateCustomer(ctx context.Context, target TargetReference) (*Customer, error)

	// CreateCheckout generates a Polar checkout URL for a product or subscription tier.
	CreateCheckout(ctx context.Context, in CreateCheckoutInput) (*CheckoutResult, error)

	// GetCustomerPortalURL generates a URL to the Polar customer portal for billing self-service.
	GetCustomerPortalURL(ctx context.Context, target TargetReference) (string, error)

	// GetActiveSubscription retrieves the current active subscription for the given target reference.
	GetActiveSubscription(ctx context.Context, target TargetReference) (*Subscription, error)

	// HasActiveSubscription reports whether the target has an active subscription to any of the given product IDs.
	HasActiveSubscription(ctx context.Context, target TargetReference, productIDs ...string) (bool, error)

	// HasBenefit reports whether the target identity has been granted a specific benefit or license key.
	HasBenefit(ctx context.Context, target TargetReference, benefitID string) (bool, error)

	// ListBenefits lists all benefits currently granted to the target identity.
	ListBenefits(ctx context.Context, target TargetReference) ([]Benefit, error)

	// HandleWebhook processes an incoming Polar webhook payload and verifies its signature in a transport-agnostic manner.
	HandleWebhook(ctx context.Context, payload []byte, signature string) (*WebhookEvent, error)
}
