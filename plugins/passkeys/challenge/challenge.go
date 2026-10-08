package challenge

import (
	"context"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	// ErrNotFound is returned when a ceremony challenge does not exist.
	ErrNotFound = errors.New("challenge: session not found")

	// ErrExpired is returned when a ceremony challenge has expired.
	ErrExpired = errors.New("challenge: session expired")

	// ErrAlreadyConsumed is returned when a ceremony challenge has already been used.
	ErrAlreadyConsumed = errors.New("challenge: session already consumed")
)

// CeremonyType classifies the WebAuthn ceremony being performed.
type CeremonyType string

const (
	// CeremonyRegistration indicates an in-flight registration ceremony.
	CeremonyRegistration CeremonyType = "registration"

	// CeremonyAuthentication indicates an in-flight authentication ceremony.
	CeremonyAuthentication CeremonyType = "authentication"
)

// Session holds the transient state of an active WebAuthn ceremony.
type Session struct {
	// ID is the unique random session token issued to the client.
	ID string `json:"id"`

	// Type distinguishes registration from authentication.
	Type CeremonyType `json:"type"`

	// UserID is the user ID if known during initiation (empty for discoverable authentication).
	UserID string `json:"user_id,omitempty"`

	// FriendlyName holds the device name provided at initiation time.
	FriendlyName string `json:"friendly_name,omitempty"`

	// Data holds the underlying WebAuthn session data (challenge bytes, timeouts, flags).
	Data webauthn.SessionData `json:"data"`

	// CreatedAt marks when the challenge was generated.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt marks when the challenge becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// ConsumedAt marks when the challenge was redeemed (nil if still unconsumed).
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// Expired reports whether the session has expired.
func (s *Session) Expired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

// Consumed reports whether the session has already been consumed.
func (s *Session) Consumed() bool {
	return s.ConsumedAt != nil
}

// Store is the persistence contract for transient WebAuthn ceremony sessions.
type Store interface {
	// Save persists a newly generated ceremony session.
	Save(ctx context.Context, s *Session) error

	// Get retrieves a ceremony session without consuming it.
	Get(ctx context.Context, id string) (*Session, error)

	// Consume atomically marks the session as used and returns it.
	// Must return ErrAlreadyConsumed on replay and ErrExpired if expired.
	Consume(ctx context.Context, id string) (*Session, error)

	// Delete removes a ceremony session.
	Delete(ctx context.Context, id string) error

	// DeleteExpired purges sessions that expired before the specified cutoff.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
