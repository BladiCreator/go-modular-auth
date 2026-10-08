package magiclink

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names published by the magic link plugin.
const (
	// EventMagicLinkRequested is emitted after a magic link has been requested and sent.
	EventMagicLinkRequested auth.EventName = "magiclink.requested"

	// EventMagicLinkConsumed is emitted after a magic link has been successfully authenticated.
	EventMagicLinkConsumed auth.EventName = "magiclink.consumed"
)

// MagicLinkRequestedPayload is the non-sensitive payload published on EventMagicLinkRequested.
// NOTE: Plaintext tokens and secrets are strictly excluded.
type MagicLinkRequestedPayload struct {
	Email     string    `json:"email"`
	Subject   string    `json:"subject"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MagicLinkConsumedPayload is the non-sensitive payload published on EventMagicLinkConsumed.
// NOTE: Plaintext tokens and secrets are strictly excluded.
type MagicLinkConsumedPayload struct {
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	SessionID  string    `json:"session_id"`
	ConsumedAt time.Time `json:"consumed_at"`
}
