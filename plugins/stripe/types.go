package stripe

import (
	"context"
	"time"
)

// SubscriptionStatus represents the lifecycle state of a Stripe subscription.
type SubscriptionStatus string

const (
	StatusActive            SubscriptionStatus = "active"
	StatusCanceled          SubscriptionStatus = "canceled"
	StatusIncomplete        SubscriptionStatus = "incomplete"
	StatusIncompleteExpired SubscriptionStatus = "incomplete_expired"
	StatusPastDue           SubscriptionStatus = "past_due"
	StatusPaused            SubscriptionStatus = "paused"
	StatusTrialing          SubscriptionStatus = "trialing"
	StatusUnpaid            SubscriptionStatus = "unpaid"
)

// Subscription represents a persistent local record of a Stripe subscription associated with a referenceId.
type Subscription struct {
	ID                   string             `json:"id"`
	Plan                 string             `json:"plan"`
	ReferenceID          string             `json:"reference_id"`
	StripeCustomerID     string             `json:"stripe_customer_id"`
	StripeSubscriptionID string             `json:"stripe_subscription_id"`
	Status               SubscriptionStatus `json:"status"`
	PeriodStart          time.Time          `json:"period_start"`
	PeriodEnd            time.Time          `json:"period_end"`
	TrialStart           *time.Time         `json:"trial_start,omitempty"`
	TrialEnd             *time.Time         `json:"trial_end,omitempty"`
	CancelAtPeriodEnd    bool               `json:"cancel_at_period_end"`
	CancelAt             *time.Time         `json:"cancel_at,omitempty"`
	CanceledAt           *time.Time         `json:"canceled_at,omitempty"`
	EndedAt              *time.Time         `json:"ended_at,omitempty"`
	Seats                int                `json:"seats"`
	BillingInterval      string             `json:"billing_interval"`
	StripeScheduleID     string             `json:"stripe_schedule_id,omitempty"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
}

// StripePlan represents a configured pricing plan mapped to Stripe Price IDs and lookup keys.
type StripePlan struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	LookupKey   string `json:"lookup_key,omitempty"`
	PriceID     string `json:"price_id"`
	SeatPriceID string `json:"seat_price_id,omitempty"`
	Currency    string `json:"currency,omitempty"`
	Seats       int    `json:"seats,omitempty"`
	Interval    string `json:"interval,omitempty"` // "month" or "year"
}

// CreateCheckoutParams holds parameters for initiating a Stripe Checkout session.
type CreateCheckoutParams struct {
	ReferenceID   string            `json:"reference_id"`
	PlanID        string            `json:"plan_id"`
	SuccessURL    string            `json:"success_url"`
	CancelURL     string            `json:"cancel_url"`
	CustomerEmail string            `json:"customer_email,omitempty"`
	Seats         int               `json:"seats,omitempty"`
	TrialDays     int               `json:"trial_days,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// UpgradeSubscriptionParams holds parameters for upgrading or downgrading an existing subscription.
type UpgradeSubscriptionParams struct {
	SubscriptionID      string `json:"subscription_id"`
	NewPlanID           string `json:"new_plan_id"`
	Seats               int    `json:"seats,omitempty"`
	ScheduleAtPeriodEnd bool   `json:"schedule_at_period_end,omitempty"`
}

// CancelSubscriptionParams holds parameters for canceling a subscription.
type CancelSubscriptionParams struct {
	SubscriptionID    string `json:"subscription_id"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
}

// BillingPortalParams holds parameters for generating a Stripe Customer Billing Portal session URL.
type BillingPortalParams struct {
	StripeCustomerID string `json:"stripe_customer_id"`
	ReturnURL        string `json:"return_url"`
}

// AuthorizeReferenceData represents context passed to the AuthorizeReference callback for access control.
type AuthorizeReferenceData struct {
	ReferenceID    string `json:"reference_id"`
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	Action         string `json:"action"`
}

// InvoiceData holds parsed payment details extracted from invoice webhooks.
type InvoiceData struct {
	InvoiceID            string    `json:"invoice_id"`
	StripeCustomerID     string    `json:"stripe_customer_id"`
	StripeSubscriptionID string    `json:"stripe_subscription_id"`
	AmountPaid           int64     `json:"amount_paid"`
	Currency             string    `json:"currency"`
	Status               string    `json:"status"`
	PaidAt               time.Time `json:"paid_at"`
}

// Callback type definitions for lifecycle extension points.
type AuthorizeReferenceFunc func(ctx context.Context, data AuthorizeReferenceData) (bool, error)
type SubscriptionCallbackFunc func(ctx context.Context, sub *Subscription) error
type InvoiceCallbackFunc func(ctx context.Context, inv *InvoiceData) error
type PlansFunc func(ctx context.Context) ([]StripePlan, error)
