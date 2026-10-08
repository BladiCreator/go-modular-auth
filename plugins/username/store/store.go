package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates the requested username record was not found in the store.
	ErrNotFound = errors.New("username store: record not found")

	// ErrConflict indicates a uniqueness constraint was violated (e.g. duplicate username or user ID).
	ErrConflict = errors.New("username store: record conflict")
)

// Record is the persistent representation of a username mapping.
type Record struct {
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`   // Display username in original casing
	Normalized string    `json:"normalized"` // Canonical search key for uniqueness & lookups
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Store is the persistence contract for username records.
// Store implementations must guarantee atomic uniqueness for both UserID and Normalized.
type Store interface {
	// Create persists a new username record. Returns ErrConflict if UserID or Normalized already exists.
	Create(ctx context.Context, rec *Record) error

	// GetByNormalized retrieves a record by its canonical normalized key.
	GetByNormalized(ctx context.Context, normalized string) (*Record, error)

	// GetByUserID retrieves a record by the Core user ID.
	GetByUserID(ctx context.Context, userID string) (*Record, error)

	// Update modifies an existing record. Returns ErrNotFound if UserID does not exist,
	// or ErrConflict if Normalized conflicts with another user.
	Update(ctx context.Context, rec *Record) error

	// Delete removes the username record for the given user ID.
	Delete(ctx context.Context, userID string) error
}
