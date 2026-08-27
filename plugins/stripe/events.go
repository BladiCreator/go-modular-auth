package stripe

const (
	// EventStripeCustomerCreated is published when a new Stripe customer is created and linked.
	EventStripeCustomerCreated = "stripe.customer.created"

	// EventStripeSubscriptionCreated is published when a subscription is successfully created.
	EventStripeSubscriptionCreated = "stripe.subscription.created"

	// EventStripeSubscriptionUpdated is published when a subscription state, tier, or period updates.
	EventStripeSubscriptionUpdated = "stripe.subscription.updated"

	// EventStripeSubscriptionDeleted is published when a subscription is canceled or deleted.
	EventStripeSubscriptionDeleted = "stripe.subscription.deleted"

	// EventStripeInvoicePaymentSucceeded is published when an invoice payment succeeds.
	EventStripeInvoicePaymentSucceeded = "stripe.invoice.payment_succeeded"

	// EventStripeInvoicePaymentFailed is published when an invoice payment attempt fails.
	EventStripeInvoicePaymentFailed = "stripe.invoice.payment_failed"

	// EventStripeWebhookReceived is published upon successfully receiving and verifying a webhook event.
	EventStripeWebhookReceived = "stripe.webhook.received"
)

// CustomerCreatedPayload represents the EventBus payload for EventStripeCustomerCreated.
type CustomerCreatedPayload struct {
	EntityType       string `json:"entity_type"` // "user" or "organization"
	EntityID         string `json:"entity_id"`
	StripeCustomerID string `json:"stripe_customer_id"`
	Email            string `json:"email,omitempty"`
}

// SubscriptionEventPayload represents the EventBus payload for subscription events.
type SubscriptionEventPayload struct {
	Subscription  *Subscription `json:"subscription"`
	StripeEventID string        `json:"stripe_event_id,omitempty"`
	EventType     string        `json:"event_type"`
}

// InvoiceEventPayload represents the EventBus payload for invoice payment events.
type InvoiceEventPayload struct {
	Invoice       *InvoiceData `json:"invoice"`
	StripeEventID string       `json:"stripe_event_id,omitempty"`
	EventType     string       `json:"event_type"`
}

// WebhookReceivedPayload represents the EventBus payload for incoming validated Stripe webhooks.
type WebhookReceivedPayload struct {
	StripeEventID string `json:"stripe_event_id"`
	EventType     string `json:"event_type"`
	RawPayload    []byte `json:"-"`
}
