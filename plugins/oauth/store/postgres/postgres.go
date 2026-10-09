// Package postgres provides a PostgreSQL-backed implementation of store.Store.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth/store"
)

// Store implements store.Store using a standard *sql.DB pool.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL store for OAuth state sessions.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// SaveState persists a newly initiated OAuth state session.
func (s *Store) SaveState(ctx context.Context, st *store.StateSession) error {
	metaJSON, err := json.Marshal(st.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_oauth_states (
			state, provider, redirect_uri, code_verifier, action, user_id, metadata, expires_at, consumed_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)`

	_, err = s.db.ExecContext(ctx, query,
		st.State, st.Provider, st.RedirectURI, st.CodeVerifier, string(st.Action),
		nullString(st.UserID), metaJSON, st.ExpiresAt, st.ConsumedAt, st.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetState retrieves a state session without consuming it.
func (s *Store) GetState(ctx context.Context, stateID string) (*store.StateSession, error) {
	query := `
		SELECT state, provider, redirect_uri, code_verifier, action, user_id, metadata, expires_at, consumed_at, created_at
		FROM auth_oauth_states
		WHERE state = $1`

	return s.scanRow(s.db.QueryRowContext(ctx, query, stateID))
}

// ConsumeState atomically validates and marks the state session as consumed.
func (s *Store) ConsumeState(ctx context.Context, stateID string, at time.Time) (*store.StateSession, error) {
	query := `
		UPDATE auth_oauth_states
		SET consumed_at = $1
		WHERE state = $2
		  AND consumed_at IS NULL
		  AND expires_at > $1
		RETURNING state, provider, redirect_uri, code_verifier, action, user_id, metadata, expires_at, consumed_at, created_at`

	st, err := s.scanRow(s.db.QueryRowContext(ctx, query, at, stateID))
	if err == nil {
		return st, nil
	}

	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// The atomic update matched 0 rows. Inspect record to return exact sentinel error.
	var (
		expiresAt  time.Time
		consumedAt *time.Time
	)
	checkQuery := `SELECT expires_at, consumed_at FROM auth_oauth_states WHERE state = $1`
	checkErr := s.db.QueryRowContext(ctx, checkQuery, stateID).Scan(&expiresAt, &consumedAt)
	if errors.Is(checkErr, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if checkErr != nil {
		return nil, checkErr
	}

	if consumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	if !at.Before(expiresAt) {
		return nil, store.ErrExpired
	}

	return nil, store.ErrNotFound
}

// DeleteState removes a state session by its state identifier.
func (s *Store) DeleteState(ctx context.Context, stateID string) error {
	query := `DELETE FROM auth_oauth_states WHERE state = $1`
	res, err := s.db.ExecContext(ctx, query, stateID)
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

// DeleteExpiredStates purges state sessions that expired before the cutoff.
func (s *Store) DeleteExpiredStates(ctx context.Context, before time.Time) (int, error) {
	query := `DELETE FROM auth_oauth_states WHERE expires_at <= $1`
	res, err := s.db.ExecContext(ctx, query, before)
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	return int(rows), err
}

func (s *Store) scanRow(row *sql.Row) (*store.StateSession, error) {
	var (
		st         store.StateSession
		actionStr  string
		userIDNull sql.NullString
		metaJSON   []byte
	)

	err := row.Scan(
		&st.State, &st.Provider, &st.RedirectURI, &st.CodeVerifier,
		&actionStr, &userIDNull, &metaJSON, &st.ExpiresAt, &st.ConsumedAt, &st.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}

	st.Action = store.Action(actionStr)
	if userIDNull.Valid {
		st.UserID = userIDNull.String
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &st.Metadata)
	}

	return &st, nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "23505")
}
