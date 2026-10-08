// Package store defines the persistence contracts for OAuth states and records.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when the requested record does not exist in store.
	ErrNotFound = errors.New("store: record not found")

	// ErrConflict is returned when attempting to insert an entity with an existing primary key.
	ErrConflict = errors.New("store: record already exists")

	// ErrExpired is returned when attempting to consume an expired state session.
	ErrExpired = errors.New("store: state expired")

	// ErrAlreadyConsumed is returned when attempting to consume an already used state session (replay attack).
	ErrAlreadyConsumed = errors.New("store: state already consumed")
)

// Action defines the intent of an in-flight OAuth flow.
type Action string

const (
	// ActionSignIn indicates an OAuth flow intended for authentication or sign up.
	ActionSignIn Action = "sign_in"

	// ActionLink indicates an OAuth flow intended for linking to an existing authenticated user.
	ActionLink Action = "link"
)

// StateSession represents an in-flight, transient OAuth state session with PKCE binding.
type StateSession struct {
	// State is the cryptographically secure random state identifier passed to the IdP.
	State string `json:"state"`

	// Provider is the identifier of the OAuth provider handling this flow (e.g., "google").
	Provider string `json:"provider"`

	// RedirectURI is the exact redirect URI bound to this authorization session.
	RedirectURI string `json:"redirect_uri"`

	// CodeVerifier is the RFC 7636 PKCE code verifier secret (empty if PKCE disabled).
	CodeVerifier string `json:"code_verifier,omitempty"`

	// Action distinguishes sign-in from explicit account linking.
	Action Action `json:"action"`

	// UserID is populated for ActionLink, binding the flow to the specific authenticated user.
	UserID string `json:"user_id,omitempty"`

	// Metadata carries optional client state, e.g. final post-login redirect path.
	Metadata map[string]string `json:"metadata,omitempty"`

	// ExpiresAt specifies the cutoff time after which this state is invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// ConsumedAt marks when this state was redeemed (nil if still active).
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`

	// CreatedAt records when the state session was initiated.
	CreatedAt time.Time `json:"created_at"`
}

// Expired reports whether the state session has expired relative to the given time.
func (s *StateSession) Expired(now time.Time) bool {
	if s.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(s.ExpiresAt)
}

// Consumed reports whether the state session has already been redeemed.
func (s *StateSession) Consumed() bool {
	return s.ConsumedAt != nil
}

// Valid reports whether the state is neither expired nor consumed.
func (s *StateSession) Valid(now time.Time) bool {
	return !s.Consumed() && !s.Expired(now)
}

// Store is the persistence contract for OAuth transient states.
// Implementations must be safe for concurrent use.
type Store interface {
	// SaveState persists a newly initiated OAuth state session.
	// Returns ErrConflict if a session with this state already exists.
	SaveState(ctx context.Context, state *StateSession) error

	// GetState retrieves a state session by its state identifier without consuming it.
	// Returns ErrNotFound if missing.
	GetState(ctx context.Context, state string) (*StateSession, error)

	// ConsumeState atomically marks the state session as consumed and returns it.
	// Must return ErrNotFound if missing, ErrExpired if expired, and ErrAlreadyConsumed on replay.
	ConsumeState(ctx context.Context, state string, at time.Time) (*StateSession, error)

	// DeleteState removes a state session by its state identifier.
	DeleteState(ctx context.Context, state string) error

	// DeleteExpiredStates purges state sessions that expired before the cutoff.
	DeleteExpiredStates(ctx context.Context, before time.Time) (int, error)
}
