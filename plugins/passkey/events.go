package passkey

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Event topic names for Passkey lifecycle events published to the EventBus.
const (
	EventRegistrationOptionsCreated   = "passkey:registration_options:created"
	EventRegistrationVerified         = "passkey:registration:verified"
	EventRegistrationFailed           = "passkey:registration:failed"
	EventAuthenticationOptionsCreated = "passkey:authentication_options:created"
	EventAuthenticationVerified       = "passkey:authentication:verified"
	EventAuthenticationFailed         = "passkey:authentication:failed"
	EventPasskeyUpdated               = "passkey:updated"
	EventPasskeyDeleted               = "passkey:deleted"
)

// RegistrationOptionsCreatedPayload is dispatched when a registration challenge is generated.
type RegistrationOptionsCreatedPayload struct {
	UserID         string         `json:"userId"`
	UserName       string         `json:"userName"`
	ChallengeToken string         `json:"challengeToken"`
	ExpiresAt      time.Time      `json:"expiresAt"`
	Extra          map[string]any `json:"extra,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// RegistrationVerifiedPayload is dispatched when a new passkey credential is authenticated and persisted.
type RegistrationVerifiedPayload struct {
	Passkey   *entity.Passkey `json:"passkey"`
	User      *entity.User    `json:"user"`
	Extra     map[string]any  `json:"extra,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// RegistrationFailedPayload is dispatched when registration ceremony verification fails.
type RegistrationFailedPayload struct {
	UserID         *string        `json:"userId,omitempty"`
	ChallengeToken string         `json:"challengeToken"`
	Reason         string         `json:"reason"`
	Extra          map[string]any `json:"extra,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// AuthenticationOptionsCreatedPayload is dispatched when an authentication assertion challenge is created.
type AuthenticationOptionsCreatedPayload struct {
	UserID         *string        `json:"userId,omitempty"`
	ChallengeToken string         `json:"challengeToken"`
	ExpiresAt      time.Time      `json:"expiresAt"`
	Extra          map[string]any `json:"extra,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// AuthenticationVerifiedPayload is dispatched when a passkey assertion is verified and session created.
type AuthenticationVerifiedPayload struct {
	Passkey   *entity.Passkey `json:"passkey"`
	User      *entity.User    `json:"user"`
	Session   *entity.Session `json:"session"`
	Extra     map[string]any  `json:"extra,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// AuthenticationFailedPayload is dispatched when an authentication assertion fails.
type AuthenticationFailedPayload struct {
	UserID         *string        `json:"userId,omitempty"`
	ChallengeToken string         `json:"challengeToken"`
	Reason         string         `json:"reason"`
	Extra          map[string]any `json:"extra,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// PasskeyUpdatedPayload is dispatched when a passkey's metadata/name is updated.
type PasskeyUpdatedPayload struct {
	Passkey   *entity.Passkey `json:"passkey"`
	OldName   *string         `json:"oldName,omitempty"`
	NewName   string          `json:"newName"`
	Timestamp time.Time       `json:"timestamp"`
}

// PasskeyDeletedPayload is dispatched when a passkey is deleted.
type PasskeyDeletedPayload struct {
	PasskeyID string    `json:"passkeyId"`
	UserID    string    `json:"userId"`
	Timestamp time.Time `json:"timestamp"`
}
