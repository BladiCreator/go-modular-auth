package polar

const (
	// EventUserCreated is published when a new user is created in the application.
	EventUserCreated = "auth:user:created"

	// EventPolarCustomerCreated is published when a new Polar customer is created and linked to a local entity.
	EventPolarCustomerCreated = "polar:customer:created"

	// EventPolarSubscriptionCreated is published when a subscription is created in Polar.
	EventPolarSubscriptionCreated = "polar:subscription:created"

	// EventPolarSubscriptionUpdated is published when a subscription state or period updates.
	EventPolarSubscriptionUpdated = "polar:subscription:updated"

	// EventPolarSubscriptionCanceled is published when a subscription is canceled or revoked.
	EventPolarSubscriptionCanceled = "polar:subscription:canceled"

	// EventPolarCustomerStateChanged is published when a customer's billing or benefit state changes in Polar.
	EventPolarCustomerStateChanged = "polar:customer:state_changed"

	// EventPolarOrderPaid is published when an order payment succeeds in Polar.
	EventPolarOrderPaid = "polar:order:paid"

	// EventPolarBenefitGranted is published when a benefit is granted to a customer in Polar.
	EventPolarBenefitGranted = "polar:benefit:granted"

	// EventPolarBenefitRevoked is published when a benefit is revoked from a customer in Polar.
	EventPolarBenefitRevoked = "polar:benefit:revoked"

	// EventPolarWebhookReceived is published upon successfully receiving and verifying a webhook event.
	EventPolarWebhookReceived = "polar:webhook:received"
)

// CustomerCreatedPayload represents the EventBus payload for EventPolarCustomerCreated.
type CustomerCreatedPayload struct {
	EntityType      string `json:"entity_type"` // "user" or "organization"
	EntityID        string `json:"entity_id"`
	PolarCustomerID string `json:"polar_customer_id"`
	Email           string `json:"email,omitempty"`
}

// SubscriptionEventPayload represents the EventBus payload for Polar subscription events.
type SubscriptionEventPayload struct {
	Subscription *Subscription `json:"subscription"`
	PolarEventID string        `json:"polar_event_id,omitempty"`
	EventType    string        `json:"event_type"`
}

// CustomerStateEventPayload represents the EventBus payload for EventPolarCustomerStateChanged.
type CustomerStateEventPayload struct {
	CustomerState *CustomerState `json:"customer_state"`
	PolarEventID  string         `json:"polar_event_id,omitempty"`
	EventType     string         `json:"event_type"`
}

// OrderEventPayload represents the EventBus payload for order payment events in Polar.
type OrderEventPayload struct {
	Order        *CustomerOrder `json:"order"`
	PolarEventID string         `json:"polar_event_id,omitempty"`
	EventType    string         `json:"event_type"`
}

// BenefitEventPayload represents the EventBus payload for benefit entitlement events in Polar.
type BenefitEventPayload struct {
	Benefit      *CustomerBenefit `json:"benefit"`
	PolarEventID string           `json:"polar_event_id,omitempty"`
	EventType    string           `json:"event_type"`
}

// WebhookReceivedPayload represents the EventBus payload for incoming validated Polar webhooks.
type WebhookReceivedPayload struct {
	PolarEventID string `json:"polar_event_id"`
	EventType    string `json:"event_type"`
	RawPayload   []byte `json:"-"`
}
