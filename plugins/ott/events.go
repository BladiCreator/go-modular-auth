package ott

import (
	"time"
)

const (
	// EventOTTGenerated is published when a new One-Time Token is successfully issued.
	EventOTTGenerated = "ott:generated"

	// EventOTTVerified is published when an OTT is successfully validated and consumed.
	EventOTTVerified = "ott:verified"
)

// OTTGeneratedPayload defines the EventBus event payload dispatched when an OTT is created.
type OTTGeneratedPayload struct {
	// SessionToken is the target session token bound to the generated OTT.
	SessionToken string `json:"session_token"`

	// Token is the issued OTT token string (or hashed token representation).
	Token string `json:"token"`

	// ExpiresAt is the timestamp when the generated token expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// OTTVerifiedPayload defines the EventBus event payload dispatched when an OTT is consumed.
type OTTVerifiedPayload struct {
	// SessionID is the unique identifier of the active session retrieved upon verification.
	SessionID string `json:"session_id"`

	// UserID is the unique identifier of the user owning the session.
	UserID string `json:"user_id"`

	// Token is the raw OTT token string that was verified.
	Token string `json:"token"`
}
