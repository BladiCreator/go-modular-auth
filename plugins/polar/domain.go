package polar

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

// SubscriptionStatus represents the lifecycle state of a Polar subscription.
type SubscriptionStatus string

const (
	StatusActive    SubscriptionStatus = "active"
	StatusCanceled  SubscriptionStatus = "canceled"
	StatusPastDue   SubscriptionStatus = "past_due"
	StatusTrialing  SubscriptionStatus = "trialing"
	StatusIncomplete SubscriptionStatus = "incomplete"
)

// Customer models a synchronized Polar customer mapped to a user or organization.
type Customer struct {
	ID              string                 `json:"id"`
	ReferenceID     string                 `json:"reference_id"`
	ReferenceType   ReferenceType          `json:"reference_type"`
	PolarCustomerID string                 `json:"polar_customer_id"`
	Email           string                 `json:"email"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// Subscription models a synchronized Polar subscription.
type Subscription struct {
	ID                  string                 `json:"id"`
	CustomerID          string                 `json:"customer_id"`
	ReferenceID         string                 `json:"reference_id"`
	ReferenceType       ReferenceType          `json:"reference_type"`
	PolarSubscriptionID string                 `json:"polar_subscription_id"`
	PolarProductID      string                 `json:"polar_product_id"`
	Status              SubscriptionStatus     `json:"status"`
	CurrentPeriodEnd    *time.Time             `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd   bool                   `json:"cancel_at_period_end"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// Active reports whether the subscription is active and within valid period.
func (s *Subscription) Active() bool {
	if s.Status != StatusActive && s.Status != StatusTrialing {
		return false
	}
	if s.CurrentPeriodEnd != nil && time.Now().After(*s.CurrentPeriodEnd) {
		return false
	}
	return true
}

// Benefit represents an entitlement, license key, or resource benefit granted via Polar.
type Benefit struct {
	ID             string                 `json:"id"`
	CustomerID     string                 `json:"customer_id"`
	ReferenceID    string                 `json:"reference_id"`
	PolarBenefitID string                 `json:"polar_benefit_id"`
	Type           string                 `json:"type"` // "license_keys", "discord", "github", "downloadables"
	IsGranted      bool                   `json:"is_granted"`
	Properties     map[string]interface{} `json:"properties,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// CreateCheckoutInput contains parameters for generating a Polar checkout URL.
type CreateCheckoutInput struct {
	Target      TargetReference        `json:"target"`
	ProductID   string                 `json:"product_id"`
	SuccessURL  string                 `json:"success_url"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CheckoutResult represents the generated Polar Checkout Session.
type CheckoutResult struct {
	CheckoutID string `json:"checkout_id"`
	URL        string `json:"url"`
}

// WebhookEvent represents a processed webhook event.
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	HandledAt time.Time              `json:"handled_at"`
}
