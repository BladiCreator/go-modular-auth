package stripe

import "context"

// Stripe defines the typed capability interface exported by the Stripe plugin module.
// Applications retrieve this via auth.Get[stripe.Stripe](engine).
type Stripe interface {
	// GetCustomer retrieves the customer mapped to the target reference (user or organization).
	GetCustomer(ctx context.Context, target TargetReference) (*Customer, error)

	// CreateCustomer explicitly provisions a customer on Stripe and stores the local mapping.
	CreateCustomer(ctx context.Context, target TargetReference) (*Customer, error)

	// CreateCheckoutSession generates a Stripe Checkout Session for subscription or payment.
	CreateCheckoutSession(ctx context.Context, in CreateCheckoutInput) (*CheckoutSession, error)

	// CreateBillingPortalSession generates a customer portal URL for self-service subscription management.
	CreateBillingPortalSession(ctx context.Context, target TargetReference, returnURL string) (*BillingPortalSession, error)

	// GetActiveSubscription retrieves the current active subscription for the given target reference.
	GetActiveSubscription(ctx context.Context, target TargetReference) (*Subscription, error)

	// HasActiveSubscription reports whether the target identity has an active subscription matching any of the given price IDs.
	// If no price IDs are specified, any active subscription is accepted.
	HasActiveSubscription(ctx context.Context, target TargetReference, priceIDs ...string) (bool, error)

	// HandleWebhook processes an incoming Stripe webhook payload and verifies its signature in a transport-agnostic manner.
	HandleWebhook(ctx context.Context, payload []byte, signature string) (*WebhookEvent, error)
}
