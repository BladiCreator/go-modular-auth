// Package store defines the persistence contract for OIDC authentication state sessions in GoModularAuth.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested state session does not exist.
	ErrNotFound = errors.New("oidc store: state session not found")

	// ErrConflict indicates that a state session with this identifier already exists.
	ErrConflict = errors.New("oidc store: state session conflict")

	// ErrStateConsumed indicates that the state session was already used (single-use violation).
	ErrStateConsumed = errors.New("oidc store: state session already consumed")
)

// Action denotes the purpose of the OIDC authorization flow.
type Action string

const (
	// ActionSignIn represents a standard authentication or registration flow.
	ActionSignIn Action = "sign_in"

	// ActionLink represents linking an external OIDC identity to an existing authenticated user.
	ActionLink Action = "link"
)

// StateSession represents an ephemeral, single-use state binding for an in-flight OIDC authentication flow.
type StateSession struct {
	State        string            `json:"state"`
	Provider     string            `json:"provider"`
	RedirectURI  string            `json:"redirect_uri"`
	CodeVerifier string            `json:"code_verifier"`
	Nonce        string            `json:"nonce"`
	Action       Action            `json:"action"`
	UserID       string            `json:"user_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	ConsumedAt   *time.Time        `json:"consumed_at,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at"`
	CreatedAt    time.Time         `json:"created_at"`
}

// Expired reports whether the state session has expired relative to the given time.
func (s *StateSession) Expired(now time.Time) bool {
	return s != nil && !now.Before(s.ExpiresAt)
}

// IsConsumed reports whether the state session has already been redeemed.
func (s *StateSession) IsConsumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// Store defines the persistent storage contract required by the OIDC plugin for state sessions.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOIDCStore struct {
//		db *gorm.DB
//	}
//
//	func (s *GormOIDCStore) GetState(ctx context.Context, state string) (*store.StateSession, error) {
//		var sess store.StateSession
//		if err := s.db.WithContext(ctx).Where("state = ?", state).First(&sess).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, store.ErrNotFound
//			}
//			return nil, err
//		}
//		return &sess, nil
//	}
//
// # Storage and Single-Use Guarantee:
//
// OIDC state sessions must be consumed atomically to prevent replay attacks and CSRF.
// When ConsumeState is called, implementations must check and set consumed_at in an atomic
// update or database transaction.
type Store interface {
	// SaveState persists a newly initiated OIDC state session.
	//
	// Function:
	//   Invoked during BeginAuth or BeginLink when initiating an OIDC flow.
	//
	// Storage:
	//   Database (GORM / SQL) or Redis with TTL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - s: New state session record.
	//
	// Returns:
	//   - error: ErrConflict if state string already exists, or infrastructure error.
	//
	// Example SQL:
	//   INSERT INTO auth_oidc_states (state, provider, redirect_uri, code_verifier, nonce, action, user_id, metadata, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	SaveState(ctx context.Context, s *StateSession) error

	// GetState retrieves a state session without consuming it.
	//
	// Function:
	//   Queries state details for pre-validation.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - state: Raw state token string.
	//
	// Returns:
	//   - *store.StateSession: Found record.
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   SELECT state, provider, redirect_uri, code_verifier, nonce, action, user_id, metadata, consumed_at, expires_at, created_at FROM auth_oidc_states WHERE state = $1 LIMIT 1;
	GetState(ctx context.Context, state string) (*StateSession, error)

	// ConsumeState atomically validates, retrieves, and marks a state session as consumed.
	//
	// Function:
	//   Invoked on CompleteAuth / CompleteLink to enforce single-use semantics and prevent CSRF replay.
	//
	// Storage:
	//   Database (GORM / SQL) - Atomic UPDATE with WHERE consumed_at IS NULL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - state: Raw state token string.
	//   - now: Current timestamp for consumption check.
	//
	// Returns:
	//   - *store.StateSession: Consumed session record.
	//   - error: ErrNotFound if missing, ErrStateConsumed if already consumed, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_oidc_states SET consumed_at = $1 WHERE state = $2 AND consumed_at IS NULL RETURNING state, provider, redirect_uri, code_verifier, nonce, action, user_id, metadata, expires_at, created_at;
	ConsumeState(ctx context.Context, state string, now time.Time) (*StateSession, error)

	// DeleteState removes a state session by its identifier.
	//
	// Function:
	//   Invoked on explicit cleanup or teardown.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - state: Raw state token string.
	//
	// Returns:
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_oidc_states WHERE state = $1;
	DeleteState(ctx context.Context, state string) error

	// PurgeExpired removes all states expired before the specified instant.
	//
	// Function:
	//   Invoked by scheduled maintenance routines to purge abandoned state sessions.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - before: Expiration cutoff timestamp.
	//
	// Returns:
	//   - int: Number of deleted records.
	//   - error: Infrastructure error if operation fails.
	//
	// Example SQL:
	//   DELETE FROM auth_oidc_states WHERE expires_at < $1;
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
