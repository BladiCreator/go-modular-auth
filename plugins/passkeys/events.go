package passkey

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventPasskeyRegistered is emitted when a new passkey credential is successfully registered.
	EventPasskeyRegistered auth.EventName = "passkey.registered"

	// EventPasskeyUsed is emitted when a user successfully authenticates using a passkey.
	EventPasskeyUsed auth.EventName = "passkey.used"

	// EventPasskeyRevoked is emitted when a passkey credential is deleted or revoked.
	EventPasskeyRevoked auth.EventName = "passkey.revoked"
)

// PasskeyRegisteredPayload conveys non-sensitive event metadata when a passkey is registered.
// Cryptographic keys and raw secrets are strictly excluded.
type PasskeyRegisteredPayload struct {
	UserID       string    `json:"user_id"`
	CredentialID string    `json:"credential_id"` // base64url encoded
	FriendlyName string    `json:"friendly_name"`
	AAGUID       string    `json:"aaguid,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

// PasskeyUsedPayload conveys non-sensitive event metadata when a passkey is used for authentication.
type PasskeyUsedPayload struct {
	UserID       string    `json:"user_id"`
	CredentialID string    `json:"credential_id"` // base64url encoded
	SessionID    string    `json:"session_id"`
	UsedAt       time.Time `json:"used_at"`
}

// PasskeyRevokedPayload conveys non-sensitive event metadata when a passkey is revoked.
type PasskeyRevokedPayload struct {
	UserID       string    `json:"user_id"`
	CredentialID string    `json:"credential_id"` // base64url encoded
	RevokedAt    time.Time `json:"revoked_at"`
}
