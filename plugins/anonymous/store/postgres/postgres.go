// Package postgres provides a PostgreSQL-backed implementation of store.Store.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-anonymous/store"
)

// Store implements store.Store using PostgreSQL.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL anonymous identity store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create persists a new anonymous identity record.
func (s *Store) Create(ctx context.Context, id *store.Identity) error {
	metaJSON, err := json.Marshal(id.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_anonymous_identities (
			id, user_id, expires_at, converted_at, linked_user_id, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)`

	_, err = s.db.ExecContext(ctx, query,
		id.ID, id.UserID, id.ExpiresAt, id.ConvertedAt, id.LinkedUserID, metaJSON, id.CreatedAt, id.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetByID retrieves an anonymous identity by its ID.
func (s *Store) GetByID(ctx context.Context, id string) (*store.Identity, error) {
	query := `
		SELECT id, user_id, expires_at, converted_at, linked_user_id, metadata, created_at, updated_at
		FROM auth_anonymous_identities
		WHERE id = $1`

	row := s.db.QueryRowContext(ctx, query, id)
	return scanIdentity(row)
}

// GetByUserID retrieves an anonymous identity by the Core User ID.
func (s *Store) GetByUserID(ctx context.Context, userID string) (*store.Identity, error) {
	query := `
		SELECT id, user_id, expires_at, converted_at, linked_user_id, metadata, created_at, updated_at
		FROM auth_anonymous_identities
		WHERE user_id = $1`

	row := s.db.QueryRowContext(ctx, query, userID)
	return scanIdentity(row)
}

// Update updates an existing identity record.
func (s *Store) Update(ctx context.Context, id *store.Identity) error {
	metaJSON, err := json.Marshal(id.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		UPDATE auth_anonymous_identities
		SET user_id = $1, expires_at = $2, converted_at = $3, linked_user_id = $4,
		    metadata = $5, updated_at = $6
		WHERE id = $7`

	res, err := s.db.ExecContext(ctx, query,
		id.UserID, id.ExpiresAt, id.ConvertedAt, id.LinkedUserID, metaJSON, id.UpdatedAt, id.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Delete removes an anonymous identity by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_anonymous_identities WHERE id = $1`
	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListExpired returns unconverted anonymous identities with ExpiresAt before the threshold.
func (s *Store) ListExpired(ctx context.Context, before time.Time, limit int) ([]*store.Identity, error) {
	query := `
		SELECT id, user_id, expires_at, converted_at, linked_user_id, metadata, created_at, updated_at
		FROM auth_anonymous_identities
		WHERE converted_at IS NULL AND expires_at < $1
		ORDER BY expires_at ASC`

	var (
		rows *sql.Rows
		err  error
	)
	if limit > 0 {
		query += " LIMIT $2"
		rows, err = s.db.QueryContext(ctx, query, before, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, query, before)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*store.Identity
	for rows.Next() {
		id, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanIdentity(s scanner) (*store.Identity, error) {
	var (
		id          store.Identity
		metaJSON    []byte
		convertedAt sql.NullTime
	)

	err := s.Scan(
		&id.ID,
		&id.UserID,
		&id.ExpiresAt,
		&convertedAt,
		&id.LinkedUserID,
		&metaJSON,
		&id.CreatedAt,
		&id.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}

	if convertedAt.Valid {
		id.ConvertedAt = &convertedAt.Time
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &id.Metadata)
	}

	return &id, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(strings.ToLower(msg), "unique constraint")
}
