// Package store defines the persistence contract for the bearer token authentication plugin.
package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

var (
	// ErrNotFound is returned when a requested token record does not exist in the store.
	ErrNotFound = errors.New("bearer store: token not found")

	// ErrConflict is returned when attempting to insert a record whose ID or token hash already exists.
	ErrConflict = errors.New("bearer store: token conflict")
)

// TokenRecord represents the persistent data model of a bearer token.
// The plaintext token secret is never stored; only TokenHash is persisted.
type TokenRecord struct {
	// ID is the unique record identifier.
	ID string `json:"id"`

	// TokenHash is the hex-encoded SHA-256 hash of the plaintext token.
	TokenHash string `json:"token_hash"`

	// Subject represents the authenticated principal (e.g. user ID or service account ID).
	Subject string `json:"subject"`

	// PrincipalType classifies the identity type (e.g. "user", "service_account").
	PrincipalType string `json:"principal_type"`

	// Scopes lists the authorization permissions assigned to the token.
	Scopes []string `json:"scopes"`

	// Metadata contains application-defined custom attributes.
	Metadata map[string]string `json:"metadata,omitempty"`

	// ExpiresAt is the timestamp when the token expires.
	ExpiresAt time.Time `json:"expires_at"`

	// RevokedAt is the timestamp when the token was revoked, or nil if active.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// CreatedAt is the timestamp when the token record was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the token record was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// Expired reports whether the token has expired relative to the given time.
func (r *TokenRecord) Expired(now time.Time) bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(r.ExpiresAt)
}

// Revoked reports whether the token has been marked as revoked.
func (r *TokenRecord) Revoked() bool {
	return r.RevokedAt != nil
}

// Active reports whether the token is neither expired nor revoked.
func (r *TokenRecord) Active(now time.Time) bool {
	return !r.Revoked() && !r.Expired(now)
}

// HasScope reports whether the record contains the specified scope.
func (r *TokenRecord) HasScope(scope string) bool {
	return slices.Contains(r.Scopes, scope)
}

// HasScopes reports whether the record satisfies all required scopes.
func (r *TokenRecord) HasScopes(required ...string) bool {
	for _, req := range required {
		if !r.HasScope(req) {
			return false
		}
	}
	return true
}

// Store defines persistence operations for bearer tokens.
// Implementations must be safe for concurrent use.
type Store interface {
	// Create persists a new token record.
	// Returns ErrConflict if a token with the same ID or TokenHash already exists.
	Create(ctx context.Context, record *TokenRecord) error

	// GetByID retrieves a token record by its primary ID.
	// Returns ErrNotFound if the record does not exist.
	GetByID(ctx context.Context, id string) (*TokenRecord, error)

	// GetByTokenHash retrieves a token record by the SHA-256 hash of its token.
	// Returns ErrNotFound if no matching record exists.
	GetByTokenHash(ctx context.Context, tokenHash string) (*TokenRecord, error)

	// Update updates mutable fields of an existing token record.
	// Returns ErrNotFound if the token record does not exist.
	Update(ctx context.Context, record *TokenRecord) error

	// Revoke sets the RevokedAt timestamp for a single token identified by ID.
	// Returns ErrNotFound if the record does not exist.
	Revoke(ctx context.Context, id string, revokedAt time.Time) error

	// RevokeBySubject sets the RevokedAt timestamp for all active tokens belonging to subject.
	RevokeBySubject(ctx context.Context, subject string, revokedAt time.Time) error

	// Delete permanently deletes a token record by its primary ID.
	// Returns ErrNotFound if the token record does not exist.
	Delete(ctx context.Context, id string) error

	// DeleteExpired permanently deletes tokens that expired before the specified timestamp or were revoked.
	// Returns the number of removed records.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)

	// ListBySubject retrieves all token records for a given subject.
	ListBySubject(ctx context.Context, subject string) ([]*TokenRecord, error)
}
