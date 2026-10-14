package stripe

import "errors"

var (
	// ErrCustomerNotFound indicates that no matching customer was found for the target reference.
	ErrCustomerNotFound = errors.New("stripe: customer not found")

	// ErrSubscriptionNotFound indicates that no active subscription was found.
	ErrSubscriptionNotFound = errors.New("stripe: subscription not found")

	// ErrInvalidWebhookSignature indicates the webhook signature header is invalid or failed verification.
	ErrInvalidWebhookSignature = errors.New("stripe: invalid webhook signature")

	// ErrInvalidPayload indicates the webhook payload could not be parsed or decoded.
	ErrInvalidPayload = errors.New("stripe: invalid webhook payload")

	// ErrInvalidReference indicates an empty or invalid target reference (ID or type).
	ErrInvalidReference = errors.New("stripe: invalid target reference")

	// ErrMissingAPIKey indicates the Stripe secret API key is missing or not configured.
	ErrMissingAPIKey = errors.New("stripe: missing required stripe api key")

	// ErrMissingWebhookSecret indicates the Stripe webhook signing secret is not configured.
	ErrMissingWebhookSecret = errors.New("stripe: missing required stripe webhook secret")
)
