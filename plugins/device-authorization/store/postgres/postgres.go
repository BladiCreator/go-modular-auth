// Package postgres implements store.Store using PostgreSQL database/sql.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth-device-authorization/store"
)

// Store implements store.Store on PostgreSQL.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New returns an initialized PostgreSQL device authorization store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

type txKey struct{}

func (s *Store) getExecutor(ctx context.Context) executor {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := context.WithValue(ctx, txKey{}, tx)
	if err := fn(txCtx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Create(ctx context.Context, grant *store.DeviceGrant) error {
	metaJSON, err := json.Marshal(grant.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_device_grants (
			id, client_id, device_code_hash, user_code, status, user_id,
			scope, metadata, expires_at, last_polled_at, polling_interval,
			failed_attempts, authorized_at, consumed_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err = s.getExecutor(ctx).ExecContext(ctx, query,
		grant.ID, grant.ClientID, grant.DeviceCodeHash, grant.UserCode,
		string(grant.Status), grant.UserID, grant.Scope, string(metaJSON),
		grant.ExpiresAt, grant.LastPolledAt, grant.PollingInterval,
		grant.FailedAttempts, grant.AuthorizedAt, grant.ConsumedAt,
		grant.CreatedAt, grant.UpdatedAt,
	)
	return err
}

func (s *Store) GetByDeviceCodeHash(ctx context.Context, codeHash string) (*store.DeviceGrant, error) {
	query := `
		SELECT id, client_id, device_code_hash, user_code, status, user_id,
		       scope, metadata, expires_at, last_polled_at, polling_interval,
		       failed_attempts, authorized_at, consumed_at, created_at, updated_at
		FROM auth_device_grants
		WHERE device_code_hash = $1
		LIMIT 1
	`
	var g store.DeviceGrant
	var statusStr string
	var metaStr string

	err := s.getExecutor(ctx).QueryRowContext(ctx, query, codeHash).Scan(
		&g.ID, &g.ClientID, &g.DeviceCodeHash, &g.UserCode, &statusStr, &g.UserID,
		&g.Scope, &metaStr, &g.ExpiresAt, &g.LastPolledAt, &g.PollingInterval,
		&g.FailedAttempts, &g.AuthorizedAt, &g.ConsumedAt, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	g.Status = store.DeviceStatus(statusStr)
	_ = json.Unmarshal([]byte(metaStr), &g.Metadata)
	return &g, nil
}

func (s *Store) GetByUserCode(ctx context.Context, userCode string) (*store.DeviceGrant, error) {
	query := `
		SELECT id, client_id, device_code_hash, user_code, status, user_id,
		       scope, metadata, expires_at, last_polled_at, polling_interval,
		       failed_attempts, authorized_at, consumed_at, created_at, updated_at
		FROM auth_device_grants
		WHERE user_code = $1
		LIMIT 1
	`
	var g store.DeviceGrant
	var statusStr string
	var metaStr string

	err := s.getExecutor(ctx).QueryRowContext(ctx, query, userCode).Scan(
		&g.ID, &g.ClientID, &g.DeviceCodeHash, &g.UserCode, &statusStr, &g.UserID,
		&g.Scope, &metaStr, &g.ExpiresAt, &g.LastPolledAt, &g.PollingInterval,
		&g.FailedAttempts, &g.AuthorizedAt, &g.ConsumedAt, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	g.Status = store.DeviceStatus(statusStr)
	_ = json.Unmarshal([]byte(metaStr), &g.Metadata)
	return &g, nil
}

func (s *Store) Update(ctx context.Context, grant *store.DeviceGrant) error {
	metaJSON, err := json.Marshal(grant.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		UPDATE auth_device_grants
		SET status = $1, user_id = $2, scope = $3, metadata = $4,
		    last_polled_at = $5, polling_interval = $6, failed_attempts = $7,
		    authorized_at = $8, consumed_at = $9, updated_at = $10
		WHERE id = $11
	`
	res, err := s.getExecutor(ctx).ExecContext(ctx, query,
		string(grant.Status), grant.UserID, grant.Scope, string(metaJSON),
		grant.LastPolledAt, grant.PollingInterval, grant.FailedAttempts,
		grant.AuthorizedAt, grant.ConsumedAt, time.Now(), grant.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) IncrementFailedAttempts(ctx context.Context, userCode string) (int, error) {
	query := `
		UPDATE auth_device_grants
		SET failed_attempts = failed_attempts + 1, updated_at = $1
		WHERE user_code = $2
		RETURNING failed_attempts
	`
	var attempts int
	err := s.getExecutor(ctx).QueryRowContext(ctx, query, time.Now(), userCode).Scan(&attempts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, store.ErrNotFound
		}
		return 0, err
	}
	return attempts, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_device_grants WHERE id = $1`
	res, err := s.getExecutor(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	query := `DELETE FROM auth_device_grants WHERE expires_at < $1`
	res, err := s.getExecutor(ctx).ExecContext(ctx, query, before)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
