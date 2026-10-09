package multisession

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names emitted by the multisession module.
const (
	EventSessionRevoked  auth.EventName = "multisession.session_revoked"
	EventSessionsRevoked auth.EventName = "multisession.sessions_revoked"
	EventSessionEvicted  auth.EventName = "multisession.session_evicted"
	EventMetadataUpdated auth.EventName = "multisession.metadata_updated"
)

// SessionRevokedPayload represents observational data when a single session is revoked.
type SessionRevokedPayload struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}

// SessionsRevokedPayload represents observational data when bulk sessions are revoked.
type SessionsRevokedPayload struct {
	UserID          string    `json:"user_id"`
	RevokedCount    int       `json:"revoked_count"`
	ExceptSessionID string    `json:"except_session_id,omitempty"`
	RevokedAt       time.Time `json:"revoked_at"`
	Reason          string    `json:"reason,omitempty"`
}

// SessionEvictedPayload represents observational data when a session is evicted due to concurrency limits.
type SessionEvictedPayload struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	EvictedAt time.Time `json:"evicted_at"`
	Reason    string    `json:"reason"`
}

// MetadataUpdatedPayload represents observational data when session metadata is set or changed.
type MetadataUpdatedPayload struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	UpdatedAt time.Time `json:"updated_at"`
}
