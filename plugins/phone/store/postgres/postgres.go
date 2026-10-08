// Package postgres provides a PostgreSQL persistence adapter for phone authentication.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-phone/store"
)

// Store implements store.Store backed by a PostgreSQL database using database/sql.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL phone store adapter.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreatePhone persists a new user phone identity mapping.
func (s *Store) CreatePhone(ctx context.Context, p *store.PhoneRecord) error {
	query := `
		INSERT INTO auth_phones (
			id, user_id, phone_number, verified, verified_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.ExecContext(ctx, query,
		p.ID, p.UserID, p.PhoneNumber, p.Verified, p.VerifiedAt, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetPhoneByUserID retrieves the phone record associated with the Core user ID.
func (s *Store) GetPhoneByUserID(ctx context.Context, userID string) (*store.PhoneRecord, error) {
	query := `
		SELECT id, user_id, phone_number, verified, verified_at, created_at, updated_at
		FROM auth_phones
		WHERE user_id = $1
	`
	row := s.db.QueryRowContext(ctx, query, userID)
	return scanPhone(row)
}

// GetPhoneByNumber retrieves the phone record associated with the canonical phone number.
func (s *Store) GetPhoneByNumber(ctx context.Context, phoneNumber string) (*store.PhoneRecord, error) {
	query := `
		SELECT id, user_id, phone_number, verified, verified_at, created_at, updated_at
		FROM auth_phones
		WHERE phone_number = $1
	`
	row := s.db.QueryRowContext(ctx, query, phoneNumber)
	return scanPhone(row)
}

// UpdatePhone updates an existing phone record.
func (s *Store) UpdatePhone(ctx context.Context, p *store.PhoneRecord) error {
	query := `
		UPDATE auth_phones
		SET phone_number = $1, verified = $2, verified_at = $3, updated_at = $4
		WHERE user_id = $5
	`
	res, err := s.db.ExecContext(ctx, query,
		p.PhoneNumber, p.Verified, p.VerifiedAt, p.UpdatedAt, p.UserID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeletePhone removes the phone record for the given user ID.
func (s *Store) DeletePhone(ctx context.Context, userID string) error {
	query := `DELETE FROM auth_phones WHERE user_id = $1`
	res, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// CreateOTP persists a new OTP verification record.
func (s *Store) CreateOTP(ctx context.Context, o *store.OTPRecord) error {
	query := `
		INSERT INTO auth_phone_otps (
			id, phone_number, subject, purpose, otp_hash, salt,
			expires_at, max_attempts, attempts, used_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := s.db.ExecContext(ctx, query,
		o.ID, o.PhoneNumber, o.Subject, o.Purpose, o.OTPHash, o.Salt,
		o.ExpiresAt, o.MaxAttempts, o.Attempts, o.UsedAt, o.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetActiveOTP retrieves the latest active OTP record for the phone number and purpose.
func (s *Store) GetActiveOTP(ctx context.Context, phoneNumber, purpose string, now time.Time) (*store.OTPRecord, error) {
	query := `
		SELECT id, phone_number, subject, purpose, otp_hash, salt,
		       expires_at, max_attempts, attempts, used_at, created_at
		FROM auth_phone_otps
		WHERE phone_number = $1
		  AND purpose = $2
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := s.db.QueryRowContext(ctx, query, phoneNumber, purpose)

	var o store.OTPRecord
	err := row.Scan(
		&o.ID, &o.PhoneNumber, &o.Subject, &o.Purpose, &o.OTPHash, &o.Salt,
		&o.ExpiresAt, &o.MaxAttempts, &o.Attempts, &o.UsedAt, &o.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// IncrementOTPAttempts atomically increments the failed attempt count.
func (s *Store) IncrementOTPAttempts(ctx context.Context, id string) (int, error) {
	query := `
		UPDATE auth_phone_otps
		SET attempts = attempts + 1
		WHERE id = $1
		RETURNING attempts
	`
	var attempts int
	err := s.db.QueryRowContext(ctx, query, id).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return attempts, nil
}

// MarkOTPUsed atomically marks an OTP record as consumed if it is unused and unlocked.
func (s *Store) MarkOTPUsed(ctx context.Context, id string, at time.Time) error {
	query := `
		UPDATE auth_phone_otps
		SET used_at = $2
		WHERE id = $1
		  AND used_at IS NULL
		  AND attempts < max_attempts
	`
	res, err := s.db.ExecContext(ctx, query, id, at)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrConflict
	}
	return nil
}

// RevokeOTPsByPhone revokes all active OTP records matching the phone and purpose.
func (s *Store) RevokeOTPsByPhone(ctx context.Context, phoneNumber, purpose string) error {
	query := `
		UPDATE auth_phone_otps
		SET used_at = NOW()
		WHERE phone_number = $1
		  AND purpose = $2
		  AND used_at IS NULL
	`
	_, err := s.db.ExecContext(ctx, query, phoneNumber, purpose)
	return err
}

// DeleteExpiredOTPs removes records expired or consumed prior to the cutoff timestamp.
func (s *Store) DeleteExpiredOTPs(ctx context.Context, before time.Time) (int, error) {
	query := `
		DELETE FROM auth_phone_otps
		WHERE (used_at IS NOT NULL AND used_at < $1)
		   OR expires_at < $1
	`
	res, err := s.db.ExecContext(ctx, query, before)
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}

func scanPhone(row *sql.Row) (*store.PhoneRecord, error) {
	var p store.PhoneRecord
	err := row.Scan(
		&p.ID, &p.UserID, &p.PhoneNumber, &p.Verified, &p.VerifiedAt, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, sql.ErrNoRows) && (strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "unique constraint"))
}
