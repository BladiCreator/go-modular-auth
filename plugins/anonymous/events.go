package anonymous

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventAnonymousCreated is published after an anonymous user and session are successfully created.
	EventAnonymousCreated auth.EventName = "anonymous.created"

	// EventAnonymousConverted is published after an anonymous identity is converted to a permanent account.
	EventAnonymousConverted auth.EventName = "anonymous.converted"

	// EventAnonymousLinked is published after an anonymous identity is linked to an existing permanent account.
	EventAnonymousLinked auth.EventName = "anonymous.linked"

	// EventAnonymousCleanedUp is published after expired anonymous identities have been purged.
	EventAnonymousCleanedUp auth.EventName = "anonymous.cleaned_up"
)

// CreatedPayload is the event payload for EventAnonymousCreated.
type CreatedPayload struct {
	IdentityID string    `json:"identity_id"`
	UserID     string    `json:"user_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// ConvertedPayload is the event payload for EventAnonymousConverted.
type ConvertedPayload struct {
	IdentityID  string    `json:"identity_id"`
	UserID      string    `json:"user_id"`
	Provider    string    `json:"provider"`
	ConvertedAt time.Time `json:"converted_at"`
}

// LinkedPayload is the event payload for EventAnonymousLinked.
type LinkedPayload struct {
	IdentityID      string    `json:"identity_id"`
	AnonymousUserID string    `json:"anonymous_user_id"`
	PermanentUserID string    `json:"permanent_user_id"`
	LinkedAt        time.Time `json:"linked_at"`
}

// CleanedUpPayload is the event payload for EventAnonymousCleanedUp.
type CleanedUpPayload struct {
	IdentitiesDeleted int       `json:"identities_deleted"`
	UsersDeleted      int       `json:"users_deleted"`
	SessionsRevoked   int       `json:"sessions_revoked"`
	CleanedAt         time.Time `json:"cleaned_at"`
}
