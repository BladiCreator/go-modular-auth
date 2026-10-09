// Package postgres provides a PostgreSQL implementation of store.Store using database/sql.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-admin/store"
)

type txKey struct{}

// Store implements store.Store using standard database/sql.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL admin store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

type queryable interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) executor(ctx context.Context) queryable {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

// Transaction executes fn inside a database transaction.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	txCtx := context.WithValue(ctx, txKey{}, tx)
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// UpsertUser persists or updates a user record.
func (s *Store) UpsertUser(ctx context.Context, r *store.UserRecord) error {
	metaJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_admin_users (
			user_id, email, disabled, disabled_at, disabled_reason, is_admin, role, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id) DO UPDATE SET
			email = EXCLUDED.email,
			disabled = EXCLUDED.disabled,
			disabled_at = EXCLUDED.disabled_at,
			disabled_reason = EXCLUDED.disabled_reason,
			is_admin = EXCLUDED.is_admin,
			role = EXCLUDED.role,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at`

	_, err = s.executor(ctx).ExecContext(ctx, query,
		r.UserID, r.Email, r.Disabled, r.DisabledAt, r.DisabledReason,
		r.IsAdmin, r.Role, metaJSON, r.CreatedAt, r.UpdatedAt,
	)
	return err
}

// GetUser retrieves the record by UserID.
func (s *Store) GetUser(ctx context.Context, userID string) (*store.UserRecord, error) {
	query := `
		SELECT user_id, email, disabled, disabled_at, disabled_reason, is_admin, role, metadata, created_at, updated_at
		FROM auth_admin_users
		WHERE user_id = $1 LIMIT 1`

	var r store.UserRecord
	var metaJSON []byte
	err := s.executor(ctx).QueryRowContext(ctx, query, userID).Scan(
		&r.UserID, &r.Email, &r.Disabled, &r.DisabledAt, &r.DisabledReason,
		&r.IsAdmin, &r.Role, &metaJSON, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &r.Metadata)
	}
	return &r, nil
}

// UpdateUserStatus updates the disabled status and reason.
func (s *Store) UpdateUserStatus(ctx context.Context, userID string, disabled bool, reason string, at *time.Time) error {
	query := `
		UPDATE auth_admin_users
		SET disabled = $1, disabled_reason = $2, disabled_at = $3, updated_at = $4
		WHERE user_id = $5`

	res, err := s.executor(ctx).ExecContext(ctx, query, disabled, reason, at, time.Now(), userID)
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

// DeleteUser deletes the user record.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	query := `DELETE FROM auth_admin_users WHERE user_id = $1`
	res, err := s.executor(ctx).ExecContext(ctx, query, userID)
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

// ListUsers returns paginated records.
func (s *Store) ListUsers(ctx context.Context, filter store.ListFilter) ([]*store.UserRecord, int, error) {
	var conditions []string
	var args []any
	argID := 1

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", argID))
		args = append(args, "%"+filter.Search+"%")
		argID++
	}
	if filter.Status == "active" {
		conditions = append(conditions, fmt.Sprintf("disabled = $%d", argID))
		args = append(args, false)
		argID++
	} else if filter.Status == "disabled" {
		conditions = append(conditions, fmt.Sprintf("disabled = $%d", argID))
		args = append(args, true)
		argID++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM auth_admin_users %s", whereClause)
	var total int
	if err := s.executor(ctx).QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Select query
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	selectQuery := fmt.Sprintf(`
		SELECT user_id, email, disabled, disabled_at, disabled_reason, is_admin, role, metadata, created_at, updated_at
		FROM auth_admin_users
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argID, argID+1)

	args = append(args, limit, filter.Offset)

	rows, err := s.executor(ctx).QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var result []*store.UserRecord
	for rows.Next() {
		var r store.UserRecord
		var metaJSON []byte
		if err := rows.Scan(
			&r.UserID, &r.Email, &r.Disabled, &r.DisabledAt, &r.DisabledReason,
			&r.IsAdmin, &r.Role, &metaJSON, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &r.Metadata)
		}
		result = append(result, &r)
	}

	return result, total, rows.Err()
}

// IsUserDisabled checks if user is disabled.
func (s *Store) IsUserDisabled(ctx context.Context, userID string) (bool, error) {
	query := `SELECT disabled FROM auth_admin_users WHERE user_id = $1 LIMIT 1`
	var disabled bool
	err := s.executor(ctx).QueryRowContext(ctx, query, userID).Scan(&disabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return disabled, nil
}

// IsAdmin checks if user is an administrator.
func (s *Store) IsAdmin(ctx context.Context, userID string) (bool, error) {
	query := `SELECT is_admin FROM auth_admin_users WHERE user_id = $1 LIMIT 1`
	var isAdmin bool
	err := s.executor(ctx).QueryRowContext(ctx, query, userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return isAdmin, nil
}

// SetAdminRole updates role and admin flag.
func (s *Store) SetAdminRole(ctx context.Context, userID string, isAdmin bool, role string) error {
	query := `UPDATE auth_admin_users SET is_admin = $1, role = $2, updated_at = $3 WHERE user_id = $4`
	res, err := s.executor(ctx).ExecContext(ctx, query, isAdmin, role, time.Now(), userID)
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
