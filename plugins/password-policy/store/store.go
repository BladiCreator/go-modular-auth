// Package store defines the persistence contract for password history records.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested password history was not found.
	ErrNotFound = errors.New("password-policy store: record not found")

	// ErrConflict indicates a uniqueness collision.
	ErrConflict = errors.New("password-policy store: record conflict")
)

// PasswordHistory represents a historical password hash for a user.
type PasswordHistory struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// Store defines persistence operations for password history.
type Store interface {
	// SaveHistory persists a new historical password record.
	SaveHistory(ctx context.Context, entry *PasswordHistory) error

	// GetHistory retrieves the most recent historical password records for a user, ordered newest first.
	GetHistory(ctx context.Context, userID string, limit int) ([]*PasswordHistory, error)

	// PruneHistory keeps only the most recent keepCount records for a user, deleting older records.
	PruneHistory(ctx context.Context, userID string, keepCount int) error

	// DeleteHistoryByUser removes all history records for a user (e.g. account deletion).
	DeleteHistoryByUser(ctx context.Context, userID string) error
}
