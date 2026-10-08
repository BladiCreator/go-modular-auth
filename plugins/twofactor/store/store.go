package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates the requested twofactor record was not found in the store.
	ErrNotFound = errors.New("twofactor store: record not found")

	// ErrConflict indicates a uniqueness constraint was violated or atomic update failed.
	ErrConflict = errors.New("twofactor store: record conflict")
)

// FactorRecord is the persistent model for an MFA factor.
type FactorRecord struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Type              string     `json:"type"`
	Label             string     `json:"label,omitempty"`
	EncryptedSecret   string     `json:"encrypted_secret"`
	Confirmed         bool       `json:"confirmed"`
	ConfirmedAt       *time.Time `json:"confirmed_at,omitempty"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	LastUsedTimeStep  int64      `json:"last_used_time_step"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// RecoveryCodeRecord is the persistent model for a hashed backup recovery code.
type RecoveryCodeRecord struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CodeHash  string     `json:"code_hash"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ChallengeRecord is the persistent fallback model for ephemeral MFA challenges.
type ChallengeRecord struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Store is the persistence contract for the twofactor plugin.
type Store interface {
	// SaveFactor persists a newly created factor record.
	SaveFactor(ctx context.Context, f *FactorRecord) error

	// GetFactor retrieves a factor record by its ID.
	GetFactor(ctx context.Context, factorID string) (*FactorRecord, error)

	// ListFactorsByUser returns all factors belonging to a user.
	ListFactorsByUser(ctx context.Context, userID string) ([]*FactorRecord, error)

	// UpdateFactor modifies an existing factor record.
	UpdateFactor(ctx context.Context, f *FactorRecord) error

	// DeleteFactor removes a single factor record by its ID.
	DeleteFactor(ctx context.Context, factorID string) error

	// DeleteFactorsByUser removes all factor records for a given user.
	DeleteFactorsByUser(ctx context.Context, userID string) error

	// SaveRecoveryCodes persists a batch of hashed recovery code records.
	SaveRecoveryCodes(ctx context.Context, codes []*RecoveryCodeRecord) error

	// ListActiveRecoveryCodesByUser returns all unused recovery codes for a user.
	ListActiveRecoveryCodesByUser(ctx context.Context, userID string) ([]*RecoveryCodeRecord, error)

	// MarkRecoveryCodeUsed atomically marks a recovery code as consumed.
	// Must return ErrConflict or ErrNotFound if already consumed.
	MarkRecoveryCodeUsed(ctx context.Context, id string, at time.Time) error

	// DeleteRecoveryCodesByUser removes all recovery codes for a given user.
	DeleteRecoveryCodesByUser(ctx context.Context, userID string) error

	// SaveChallenge persists a short-lived MFA challenge record.
	SaveChallenge(ctx context.Context, c *ChallengeRecord) error

	// GetChallenge retrieves an MFA challenge record by its ID.
	GetChallenge(ctx context.Context, id string) (*ChallengeRecord, error)

	// MarkChallengeUsed atomically marks an MFA challenge as consumed.
	MarkChallengeUsed(ctx context.Context, id string, at time.Time) error
}
