package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when a requested revocation record does not exist.
	ErrNotFound = errors.New("jwt store: record not found")

	// ErrConflict is returned when attempting to insert a duplicate record.
	ErrConflict = errors.New("jwt store: record conflict")
)

// RevocationRecord represents an explicit token revocation by unique ID (jti).
type RevocationRecord struct {
	JTI       string    `json:"jti"`
	Subject   string    `json:"subject,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at"`
}

// SubjectRevocationRecord represents a blanket revocation for all tokens of a subject issued before Cutoff.
type SubjectRevocationRecord struct {
	Subject   string    `json:"subject"`
	Cutoff    time.Time `json:"cutoff"`
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Store defines persistence operations for token and subject revocations.
// Implementations must be safe for concurrent use.
type Store interface {
	// RevokeToken persists an individual token revocation.
	RevokeToken(ctx context.Context, record *RevocationRecord) error

	// IsTokenRevoked reports whether the specified JTI is currently recorded as revoked.
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)

	// RevokeSubject records a subject revocation invalidating tokens issued before Cutoff.
	RevokeSubject(ctx context.Context, record *SubjectRevocationRecord) error

	// IsSubjectRevoked reports whether tokens for subject issued at issuedAt are invalidated.
	IsSubjectRevoked(ctx context.Context, subject string, issuedAt time.Time) (bool, error)

	// DeleteExpired removes token revocation records whose original expiration timestamp is in the past.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
