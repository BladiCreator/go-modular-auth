// Package store defines the persistence contract for phone identity and OTP verification.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates the requested phone or OTP record was not found in persistence.
	ErrNotFound = errors.New("phone store: record not found")

	// ErrConflict indicates a constraint violation (e.g. duplicate phone, duplicate user, or concurrent consumption).
	ErrConflict = errors.New("phone store: record conflict")
)

// PhoneRecord represents the persistent mapping between a Core User and a validated phone number.
type PhoneRecord struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	PhoneNumber string     `json:"phone_number"` // Canonical E.164 string
	Verified    bool       `json:"verified"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// OTPRecord represents the persistent verification state of an issued phone OTP.
// Adheres strictly to Core VerificationToken semantics with salt and attempt tracking.
type OTPRecord struct {
	ID          string     `json:"id"`
	PhoneNumber string     `json:"phone_number"`
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
func (r *OTPRecord) Used() bool {
	return r.UsedAt != nil
}

// Expired reports whether the OTP token has expired at the specified instant.
func (r *OTPRecord) Expired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// Locked reports whether failed verification attempts have exceeded the maximum threshold.
func (r *OTPRecord) Locked() bool {
	return r.Attempts >= r.MaxAttempts
}

// Store defines the persistence contract required for phone identity and OTP lifecycle.
// The Store is the authoritative source of truth.
type Store interface {
	// CreatePhone persists a new user phone identity mapping.
	// Returns ErrConflict if UserID or PhoneNumber is already registered.
	CreatePhone(ctx context.Context, p *PhoneRecord) error

	// GetPhoneByUserID retrieves the phone record associated with the Core user ID.
	GetPhoneByUserID(ctx context.Context, userID string) (*PhoneRecord, error)

	// GetPhoneByNumber retrieves the phone record associated with the canonical phone number.
	GetPhoneByNumber(ctx context.Context, phoneNumber string) (*PhoneRecord, error)

	// UpdatePhone updates an existing phone record.
	// Returns ErrNotFound if the record does not exist, or ErrConflict if PhoneNumber conflicts.
	UpdatePhone(ctx context.Context, p *PhoneRecord) error

	// DeletePhone removes the phone record for the given user ID.
	DeletePhone(ctx context.Context, userID string) error

	// CreateOTP persists a new OTP verification record.
	CreateOTP(ctx context.Context, o *OTPRecord) error

	// GetActiveOTP retrieves the latest active (unconsumed, unexpired, unlocked) OTP record
	// for the given phone number and purpose.
	GetActiveOTP(ctx context.Context, phoneNumber, purpose string, now time.Time) (*OTPRecord, error)

	// IncrementOTPAttempts atomically increments the failed attempt count for the record.
	// Returns the updated count.
	IncrementOTPAttempts(ctx context.Context, id string) (int, error)

	// MarkOTPUsed atomically marks an OTP record as consumed if it is unused and unlocked.
	// Must return ErrConflict if the record was already consumed or locked.
	MarkOTPUsed(ctx context.Context, id string, at time.Time) error

	// RevokeOTPsByPhone revokes/marks used all active OTP records matching the phone and purpose.
	RevokeOTPsByPhone(ctx context.Context, phoneNumber, purpose string) error

	// DeleteExpiredOTPs removes records expired or consumed prior to the cutoff timestamp.
	DeleteExpiredOTPs(ctx context.Context, before time.Time) (int, error)
}
