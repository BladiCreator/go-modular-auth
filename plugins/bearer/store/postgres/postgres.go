// Package postgres provides a PostgreSQL-backed implementation of store.Store.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-bearer/store"
)

// Store implements store.Store using a standard *sql.DB connection pool.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL bearer token store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create persists a new token record.
func (s *Store) Create(ctx context.Context, r *store.TokenRecord) error {
	scopesJSON, err := json.Marshal(r.Scopes)
	if err != nil {
		scopesJSON = []byte("[]")
	}
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_bearer_tokens (
			id, token_hash, subject, principal_type, scopes, metadata, expires_at, revoked_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)`

	_, err = s.db.ExecContext(ctx, query,
		r.ID, r.TokenHash, r.Subject, r.PrincipalType, scopesJSON, metaJSON,
		r.ExpiresAt, r.RevokedAt, r.CreatedAt, r.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetByID retrieves a token record by its primary ID.
func (s *Store) GetByID(ctx context.Context, id string) (*store.TokenRecord, error) {
	query := `
		SELECT id, token_hash, subject, principal_type, scopes, metadata, expires_at, revoked_at, created_at, updated_at
		FROM auth_bearer_tokens
		WHERE id = $1`

	return s.scanRow(s.db.QueryRowContext(ctx, query, id))
}

// GetByTokenHash retrieves a token record by the SHA-256 hash of its token.
func (s *Store) GetByTokenHash(ctx context.Context, tokenHash string) (*store.TokenRecord, error) {
	query := `
		SELECT id, token_hash, subject, principal_type, scopes, metadata, expires_at, revoked_at, created_at, updated_at
		FROM auth_bearer_tokens
		WHERE token_hash = $1`

	return s.scanRow(s.db.QueryRowContext(ctx, query, tokenHash))
}

// Update updates mutable fields of an existing token record.
func (s *Store) Update(ctx context.Context, r *store.TokenRecord) error {
	scopesJSON, err := json.Marshal(r.Scopes)
	if err != nil {
		scopesJSON = []byte("[]")
	}
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		UPDATE auth_bearer_tokens
		SET token_hash = $1, subject = $2, principal_type = $3, scopes = $4, metadata = $5,
		    expires_at = $6, revoked_at = $7, updated_at = $8
		WHERE id = $9`

	res, err := s.db.ExecContext(ctx, query,
		r.TokenHash, r.Subject, r.PrincipalType, scopesJSON, metaJSON,
		r.ExpiresAt, r.RevokedAt, r.UpdatedAt, r.ID,
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

// Revoke sets the RevokedAt timestamp for a single token.
func (s *Store) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	query := `
		UPDATE auth_bearer_tokens
		SET revoked_at = $1, updated_at = $1
		WHERE id = $2 AND revoked_at IS NULL`

	res, err := s.db.ExecContext(ctx, query, revokedAt, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// Check if it exists to return appropriate error
		var exists bool
		_ = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM auth_bearer_tokens WHERE id = $1)`, id).Scan(&exists)
		if !exists {
			return store.ErrNotFound
		}
		// Already revoked: idempotent success
	}
	return nil
}

// RevokeBySubject sets the RevokedAt timestamp for all active tokens belonging to subject.
func (s *Store) RevokeBySubject(ctx context.Context, subject string, revokedAt time.Time) error {
	query := `
		UPDATE auth_bearer_tokens
		SET revoked_at = $1, updated_at = $1
		WHERE subject = $2 AND revoked_at IS NULL`

	_, err := s.db.ExecContext(ctx, query, revokedAt, subject)
	return err
}

// Delete permanently removes a token record by its primary ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_bearer_tokens WHERE id = $1`
	res, err := s.db.ExecContext(ctx, query, id)
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

// DeleteExpired permanently deletes tokens that expired or were revoked before the given timestamp.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	query := `
		DELETE FROM auth_bearer_tokens
		WHERE (expires_at <= $1 AND expires_at != '0001-01-01 00:00:00+00')
		   OR (revoked_at IS NOT NULL AND revoked_at <= $1)`

	res, err := s.db.ExecContext(ctx, query, before)
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	return int(rows), err
}

// ListBySubject retrieves all token records for a given subject.
func (s *Store) ListBySubject(ctx context.Context, subject string) ([]*store.TokenRecord, error) {
	query := `
		SELECT id, token_hash, subject, principal_type, scopes, metadata, expires_at, revoked_at, created_at, updated_at
		FROM auth_bearer_tokens
		WHERE subject = $1
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*store.TokenRecord
	for rows.Next() {
		var (
			rec                   store.TokenRecord
			scopesJSON, metaJSON []byte
		)
		if err := rows.Scan(
			&rec.ID, &rec.TokenHash, &rec.Subject, &rec.PrincipalType,
			&scopesJSON, &metaJSON, &rec.ExpiresAt, &rec.RevokedAt,
			&rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(scopesJSON) > 0 {
			_ = json.Unmarshal(scopesJSON, &rec.Scopes)
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &rec.Metadata)
		}
		results = append(results, &rec)
	}
	return results, rows.Err()
}

func (s *Store) scanRow(row *sql.Row) (*store.TokenRecord, error) {
	var (
		rec                   store.TokenRecord
		scopesJSON, metaJSON []byte
	)
	err := row.Scan(
		&rec.ID, &rec.TokenHash, &rec.Subject, &rec.PrincipalType,
		&scopesJSON, &metaJSON, &rec.ExpiresAt, &rec.RevokedAt,
		&rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(scopesJSON) > 0 {
		_ = json.Unmarshal(scopesJSON, &rec.Scopes)
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &rec.Metadata)
	}
	return &rec, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "23505")
}
