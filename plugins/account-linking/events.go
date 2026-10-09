package accountlinking

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventAccountLinked is emitted when an authentication provider account is successfully linked to a user.
	EventAccountLinked auth.EventName = "account.linked"

	// EventAccountUnlinked is emitted when an authentication provider account is detached from a user.
	EventAccountUnlinked auth.EventName = "account.unlinked"

	// EventLinkFailed is emitted when an account linking attempt fails (conflict, validation, authorization).
	EventLinkFailed auth.EventName = "account.link.failed"

	// EventUnlinkFailed is emitted when an account unlinking attempt is blocked (e.g. final auth method).
	EventUnlinkFailed auth.EventName = "account.unlink.failed"

	// EventTicketCreated is emitted when a new linking ceremony ticket is issued.
	EventTicketCreated auth.EventName = "account.ticket.created"
)

// AccountLinkedPayload carries structured details for EventAccountLinked.
type AccountLinkedPayload struct {
	UserID       string    `json:"user_id"`
	AccountID    string    `json:"account_id"`
	Provider     string    `json:"provider"`
	ProviderID   string    `json:"provider_id"`
	ActorSubject string    `json:"actor_subject,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// AccountUnlinkedPayload carries structured details for EventAccountUnlinked.
type AccountUnlinkedPayload struct {
	UserID       string    `json:"user_id"`
	AccountID    string    `json:"account_id"`
	Provider     string    `json:"provider"`
	ProviderID   string    `json:"provider_id"`
	ActorSubject string    `json:"actor_subject,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// LinkFailedPayload carries audit details when a link operation fails.
type LinkFailedPayload struct {
	UserID       string    `json:"user_id"`
	Provider     string    `json:"provider"`
	ProviderID   string    `json:"provider_id"`
	Reason       string    `json:"reason"`
	ActorSubject string    `json:"actor_subject,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// UnlinkFailedPayload carries audit details when an unlink operation fails.
type UnlinkFailedPayload struct {
	UserID       string    `json:"user_id"`
	AccountID    string    `json:"account_id,omitempty"`
	Provider     string    `json:"provider,omitempty"`
	ProviderID   string    `json:"provider_id,omitempty"`
	Reason       string    `json:"reason"`
	ActorSubject string    `json:"actor_subject,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// TicketCreatedPayload carries audit details when a linking ticket is generated.
type TicketCreatedPayload struct {
	TicketID       string    `json:"ticket_id"`
	UserID         string    `json:"user_id"`
	TargetProvider string    `json:"target_provider,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	ActorSubject   string    `json:"actor_subject,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}
