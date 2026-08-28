package polar

import (
	"time"
)

// Subscription represents a local subscription record linked to a Polar subscription.
type Subscription struct {
	ID                  string            `json:"id"`
	PolarSubscriptionID string            `json:"polar_subscription_id"`
	PolarCustomerID     string            `json:"polar_customer_id"`
	ReferenceID         string            `json:"reference_id"`
	Plan                string            `json:"plan"`
	ProductID           string            `json:"product_id,omitempty"`
	PriceID             string            `json:"price_id,omitempty"`
	Status              string            `json:"status"` // "active", "trialing", "canceled", "past_due", "unpaid"
	Amount              int64             `json:"amount"`
	Currency            string            `json:"currency"`
	Interval            string            `json:"interval"` // "month", "year"
	CurrentPeriodStart  time.Time         `json:"current_period_start"`
	CurrentPeriodEnd    time.Time         `json:"current_period_end"`
	CancelAtPeriodEnd   bool              `json:"cancel_at_period_end"`
	Seats               int               `json:"seats,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// PolarPlan defines a subscription plan or product tier in Polar.
type PolarPlan struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	ProductID   string            `json:"product_id"`
	PriceID     string            `json:"price_id"`
	PriceAmount int64             `json:"price_amount"`
	Currency    string            `json:"currency"`
	Interval    string            `json:"interval"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CreateCheckoutParams contains request inputs for initializing a Polar Checkout session.
type CreateCheckoutParams struct {
	ProductPriceID         string            `json:"product_price_id"`
	ProductSlug            string            `json:"product_slug,omitempty"`
	SuccessURL             string            `json:"success_url"`
	CancelURL              string            `json:"cancel_url,omitempty"`
	ReferenceID            string            `json:"reference_id"`
	CustomerEmail          string            `json:"customer_email,omitempty"`
	CustomerName           string            `json:"customer_name,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	AuthenticatedUsersOnly bool              `json:"authenticated_users_only,omitempty"`
	AllowDiscountCodes     bool              `json:"allow_discount_codes,omitempty"`
	TrialDays              int               `json:"trial_days,omitempty"`
}

// CustomerPortalParams contains options for creating a Polar Customer Portal session.
type CustomerPortalParams struct {
	PolarCustomerID string `json:"polar_customer_id,omitempty"`
	ReferenceID     string `json:"reference_id"`
	ReturnURL       string `json:"return_url,omitempty"`
}

// CustomerState summarizes the active billing state of a customer in Polar.
type CustomerState struct {
	PolarCustomerID     string             `json:"polar_customer_id"`
	ReferenceID         string             `json:"reference_id"`
	ActiveSubscriptions []*Subscription    `json:"active_subscriptions"`
	GrantedBenefits     []*CustomerBenefit `json:"granted_benefits"`
	MeterBalances       []*CustomerMeter   `json:"meter_balances"`
}

// CustomerBenefit represents an entitled benefit granted by Polar.
type CustomerBenefit struct {
	ID             string    `json:"id"`
	PolarBenefitID string    `json:"polar_benefit_id"`
	Type           string    `json:"type"`
	Description    string    `json:"description,omitempty"`
	GrantedAt      time.Time `json:"granted_at"`
}

// CustomerOrder represents an order or payment record in Polar.
type CustomerOrder struct {
	ID           string    `json:"id"`
	PolarOrderID string    `json:"polar_order_id"`
	Amount       int64     `json:"amount"`
	Currency     string    `json:"currency"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// CustomerMeter represents a usage meter balance in Polar.
type CustomerMeter struct {
	MeterID  string  `json:"meter_id"`
	Name     string  `json:"name"`
	Consumed float64 `json:"consumed"`
	Balance  float64 `json:"balance"`
}

// IngestEventParams represents a request to report usage event ingestion to Polar.
type IngestEventParams struct {
	EventName          string                 `json:"event_name"`
	CustomerExternalID string                 `json:"customer_external_id,omitempty"`
	PolarCustomerID    string                 `json:"polar_customer_id,omitempty"`
	Timestamp          time.Time              `json:"timestamp,omitempty"`
	Metadata           map[string]string      `json:"metadata,omitempty"`
	Properties         map[string]interface{} `json:"properties,omitempty"`
}

// IngestEventResult represents the response from Polar usage event ingestion.
type IngestEventResult struct {
	IngestID   string    `json:"ingest_id"`
	RecordedAt time.Time `json:"recorded_at"`
}

// CancelSubscriptionParams options for canceling an active subscription.
type CancelSubscriptionParams struct {
	SubscriptionID    string `json:"subscription_id"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
}

// IsActiveOrTrialing returns true if a subscription is currently active or trialing.
func IsActiveOrTrialing(sub *Subscription) bool {
	if sub == nil {
		return false
	}
	return sub.Status == "active" || sub.Status == "trialing"
}
