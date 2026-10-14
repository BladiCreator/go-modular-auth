package stripe

import "time"

// ReferenceType specifies the entity type bound to a billing resource.
type ReferenceType string

const (
	// ReferenceUser binds the resource to an individual core User.
	ReferenceUser ReferenceType = "user"

	// ReferenceOrganization binds the resource to a multi-tenant Organization.
	ReferenceOrganization ReferenceType = "organization"
)

// TargetReference represents a polymorphic target identity (user or organization).
type TargetReference struct {
	Type ReferenceType `json:"type"`
	ID   string        `json:"id"`
}

// SubscriptionStatus represents the lifecycle state of a Stripe subscription.
type SubscriptionStatus string

const (
	StatusActive     SubscriptionStatus = "active"
	StatusPastDue    SubscriptionStatus = "past_due"
	StatusCanceled   SubscriptionStatus = "canceled"
	StatusIncomplete SubscriptionStatus = "incomplete"
	StatusTrialing   SubscriptionStatus = "trialing"
)

// Customer models a synchronized Stripe customer mapped to a user or organization.
type Customer struct {
	ID               string                 `json:"id"`
	ReferenceID      string                 `json:"reference_id"`
	ReferenceType    ReferenceType          `json:"reference_type"`
	StripeCustomerID string                 `json:"stripe_customer_id"`
	Email            string                 `json:"email"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// Subscription models a synchronized Stripe subscription.
type Subscription struct {
	ID                   string                 `json:"id"`
	CustomerID           string                 `json:"customer_id"`
	ReferenceID          string                 `json:"reference_id"`
	ReferenceType        ReferenceType          `json:"reference_type"`
	StripeSubscriptionID string                 `json:"stripe_subscription_id"`
	StripePriceID        string                 `json:"stripe_price_id"`
	Status               SubscriptionStatus     `json:"status"`
	Seats                int64                  `json:"seats,omitempty"`
	CancelAtPeriodEnd    bool                   `json:"cancel_at_period_end"`
	CurrentPeriodStart   time.Time              `json:"current_period_start"`
	CurrentPeriodEnd     time.Time              `json:"current_period_end"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// Active reports whether the subscription grants current access.
func (s *Subscription) Active() bool {
	return (s.Status == StatusActive || s.Status == StatusTrialing) && time.Now().Before(s.CurrentPeriodEnd)
}

// CreateCheckoutInput contains parameters for creating a Stripe Checkout Session.
type CreateCheckoutInput struct {
	Target     TargetReference        `json:"target"`
	PriceID    string                 `json:"price_id"`
	SuccessURL string                 `json:"success_url"`
	CancelURL  string                 `json:"cancel_url"`
	Mode       string                 `json:"mode,omitempty"` // "subscription" or "payment"
	Seats      int64                  `json:"seats,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// CheckoutSession represents the created Stripe Checkout Session result.
type CheckoutSession struct {
	SessionID string `json:"session_id"`
	URL       string `json:"url"`
}

// BillingPortalSession represents a created Stripe Billing Customer Portal session.
type BillingPortalSession struct {
	URL string `json:"url"`
}

// WebhookEvent represents a processed webhook event.
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	HandledAt time.Time              `json:"handled_at"`
}
