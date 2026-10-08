// Package store defines the persistence contract for email OTP verification state.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates the requested OTP record was not found.
	ErrNotFound = errors.New("email-otp store: not found")

	// ErrConflict indicates an atomic state conflict (e.g., token already consumed or locked).
	ErrConflict = errors.New("email-otp store: conflict")
)

// Record represents the persistent state of an issued email OTP token.
// It adheres to Core VerificationToken semantics while adding attempt tracking and salting.
type Record struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Subject     string     `json:"subject"`
	Purpose     string     `json:"purpose"`
	OTPHash     string     `json:"otp_hash"`
	Salt        string     `json:"salt"`
	ExpiresAt   time.Time  `json:"expires_at"`
	MaxAttempts int        `json:"max_attempts"`
	Attempts    int        `json:"attempts"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Used reports whether the OTP token has already been consumed.
func (r *Record) Used() bool {
	return r.UsedAt != nil
}

// Expired reports whether the OTP token has expired at the given instant.
func (r *Record) Expired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// Locked reports whether failed verification attempts have exceeded the allowed limit.
func (r *Record) Locked() bool {
	return r.Attempts >= r.MaxAttempts
}

// Store defines the persistence contract required for email OTP operations.
// The store is the authoritative source of truth for OTP lifecycle and attempt limits.
type Store interface {
	// Create persists a new OTP record.
	Create(ctx context.Context, rec *Record) error

	// GetActiveByEmail retrieves the latest active (unconsumed, unexpired, unlocked) record for the given email.
	GetActiveByEmail(ctx context.Context, email string, now time.Time) (*Record, error)

	// IncrementAttempts atomically increments the failed attempt count for the record.
	// Returns the updated attempt count.
	IncrementAttempts(ctx context.Context, id string) (int, error)

	// MarkUsed atomically sets UsedAt if the record is still unused and not locked.
	// Must return ErrConflict if the record was already consumed or locked.
	MarkUsed(ctx context.Context, id string, at time.Time) error

	// RevokeByEmail revokes or deletes all active OTP records for the email address.
	RevokeByEmail(ctx context.Context, email string) error

	// DeleteExpired purges expired or consumed records older than the cutoff timestamp.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
