package polar

import "errors"

var (
	// ErrCustomerNotFound indicates that no matching customer was found for the target reference.
	ErrCustomerNotFound = errors.New("polar: customer not found")

	// ErrSubscriptionNotFound indicates that no active subscription was found.
	ErrSubscriptionNotFound = errors.New("polar: subscription not found")

	// ErrBenefitNotFound indicates that the requested benefit was not granted or found.
	ErrBenefitNotFound = errors.New("polar: benefit not found")

	// ErrInvalidWebhookSignature indicates the webhook signature header is invalid or failed verification.
	ErrInvalidWebhookSignature = errors.New("polar: invalid webhook signature")

	// ErrInvalidPayload indicates the webhook payload could not be parsed or decoded.
	ErrInvalidPayload = errors.New("polar: invalid webhook payload")

	// ErrInvalidReference indicates an empty or invalid target reference (ID or type).
	ErrInvalidReference = errors.New("polar: invalid target reference")

	// ErrMissingAccessToken indicates the Polar Access Token is missing or not configured.
	ErrMissingAccessToken = errors.New("polar: missing required polar access token")

	// ErrMissingWebhookSecret indicates the Polar webhook signing secret is not configured.
	ErrMissingWebhookSecret = errors.New("polar: missing required polar webhook secret")
)
