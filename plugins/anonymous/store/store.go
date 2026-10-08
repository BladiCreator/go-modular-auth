// Package store defines the persistence contract for the anonymous authentication plugin.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when an anonymous identity does not exist in the store.
	ErrNotFound = errors.New("anonymous store: identity not found")

	// ErrConflict is returned when an identity or user ID uniqueness constraint is violated.
	ErrConflict = errors.New("anonymous store: identity conflict")
)

// Identity represents the persistent record of an anonymous identity in the system.
type Identity struct {
	// ID is the unique identifier for this anonymous identity record.
	ID string `json:"id"`

	// UserID is the associated GoModularAuth Core user ID.
	UserID string `json:"user_id"`

	// ExpiresAt specifies the exact timestamp when this anonymous identity expires.
	ExpiresAt time.Time `json:"expires_at"`

	// ConvertedAt is set when the identity is upgraded to a permanent account or merged.
	ConvertedAt *time.Time `json:"converted_at,omitempty"`

	// LinkedUserID holds the ID of the target permanent user if this identity was merged/linked.
	LinkedUserID string `json:"linked_user_id,omitempty"`

	// Metadata carries arbitrary application-specific key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is the timestamp when this anonymous identity was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this identity was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// Expired reports whether the anonymous identity is expired at the given instant.
func (i *Identity) Expired(now time.Time) bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(i.ExpiresAt)
}

// Converted reports whether the identity has been converted to permanent or linked.
func (i *Identity) Converted() bool {
	return i.ConvertedAt != nil
}

// IsActive reports whether the identity is currently valid, unexpired, and unconverted.
func (i *Identity) IsActive(now time.Time) bool {
	return !i.Converted() && !i.Expired(now)
}

// Store defines the persistence operations for anonymous identities.
// Concrete adapters (Memory, PostgreSQL) implement this contract.
type Store interface {
	// Create persists a new anonymous identity record.
	// Returns ErrConflict if an identity with the same ID or UserID already exists.
	Create(ctx context.Context, identity *Identity) error

	// GetByID retrieves an anonymous identity by its identity ID.
	// Returns ErrNotFound if not found.
	GetByID(ctx context.Context, id string) (*Identity, error)

	// GetByUserID retrieves an anonymous identity by the Core User ID.
	// Returns ErrNotFound if not found.
	GetByUserID(ctx context.Context, userID string) (*Identity, error)

	// Update updates mutable fields of an existing identity record.
	// Returns ErrNotFound if the identity does not exist.
	Update(ctx context.Context, identity *Identity) error

	// Delete removes an anonymous identity by its identity ID.
	// Returns ErrNotFound if the identity does not exist.
	Delete(ctx context.Context, id string) error

	// ListExpired returns unconverted anonymous identities whose ExpiresAt is before the given instant,
	// up to the specified limit (0 for default/all).
	ListExpired(ctx context.Context, before time.Time, limit int) ([]*Identity, error)
}
