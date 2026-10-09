package oidc

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names emitted by the OIDC plugin.
const (
	EventOIDCAuthenticated   auth.EventName = "oidc.authenticated"
	EventOIDCAccountLinked   auth.EventName = "oidc.account_linked"
	EventOIDCAccountUnlinked auth.EventName = "oidc.account_unlinked"
	EventOIDCFailed          auth.EventName = "oidc.failed"
)

// AuthenticatedPayload describes an OIDC sign-in or registration event.
type AuthenticatedPayload struct {
	UserID     string    `json:"user_id"`
	AccountID  string    `json:"account_id"`
	Provider   string    `json:"provider"`
	Subject    string    `json:"subject"`
	IsNewUser  bool      `json:"is_new_user"`
	OccurredAt time.Time `json:"occurred_at"`
}

// LinkedPayload describes an external OIDC provider linkage event.
type LinkedPayload struct {
	UserID     string    `json:"user_id"`
	AccountID  string    `json:"account_id"`
	Provider   string    `json:"provider"`
	Subject    string    `json:"subject"`
	OccurredAt time.Time `json:"occurred_at"`
}

// UnlinkedPayload describes an unlinking event.
type UnlinkedPayload struct {
	UserID     string    `json:"user_id"`
	AccountID  string    `json:"account_id"`
	Provider   string    `json:"provider"`
	OccurredAt time.Time `json:"occurred_at"`
}

// FailedPayload describes an authentication failure event.
type FailedPayload struct {
	Provider   string    `json:"provider"`
	Reason     string    `json:"reason"`
	OccurredAt time.Time `json:"occurred_at"`
}
