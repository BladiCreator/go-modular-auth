// Package postgres provides a PostgreSQL persistence adapter for API keys.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-apikeys/store"
)

// Store implements store.Store backed by PostgreSQL using database/sql.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL API key store adapter.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create persists a new API key record.
func (s *Store) Create(ctx context.Context, key *store.APIKey) error {
	scopesJSON, err := json.Marshal(key.Scopes)
	if err != nil {
		return fmt.Errorf("apikeys postgres: marshal scopes: %w", err)
	}

	permsJSON, err := json.Marshal(key.Permissions)
	if err != nil {
		return fmt.Errorf("apikeys postgres: marshal permissions: %w", err)
	}

	metaJSON, err := json.Marshal(key.Metadata)
	if err != nil {
		return fmt.Errorf("apikeys postgres: marshal metadata: %w", err)
	}

	query := `
		INSERT INTO auth_api_keys (
			id, name, prefix, key_hash, user_id, organization_id, service_id,
			scopes, permissions, metadata, expires_at, revoked_at,
			last_used_at, last_used_ip, last_used_ua, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	_, err = s.db.ExecContext(ctx, query,
		key.ID,
		key.Name,
		key.Prefix,
		key.KeyHash,
		nullIfEmpty(key.UserID),
		nullIfEmpty(key.OrganizationID),
		nullIfEmpty(key.ServiceID),
		string(scopesJSON),
		string(permsJSON),
		string(metaJSON),
		key.ExpiresAt,
		key.RevokedAt,
		key.LastUsedAt,
		key.LastUsedIP,
		key.LastUsedUA,
		key.CreatedAt,
		key.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetByID retrieves an API key by unique ID.
func (s *Store) GetByID(ctx context.Context, id string) (*store.APIKey, error) {
	query := `
		SELECT id, name, prefix, key_hash, user_id, organization_id, service_id,
		       scopes, permissions, metadata, expires_at, revoked_at,
		       last_used_at, last_used_ip, last_used_ua, created_at, updated_at
		FROM auth_api_keys
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, query, id)
	return scanKey(row)
}

// GetByHash retrieves an API key by SHA-256 hash digest.
func (s *Store) GetByHash(ctx context.Context, keyHash string) (*store.APIKey, error) {
	query := `
		SELECT id, name, prefix, key_hash, user_id, organization_id, service_id,
		       scopes, permissions, metadata, expires_at, revoked_at,
		       last_used_at, last_used_ip, last_used_ua, created_at, updated_at
		FROM auth_api_keys
		WHERE key_hash = $1
	`
	row := s.db.QueryRowContext(ctx, query, keyHash)
	return scanKey(row)
}

// Update modifies an existing API key record.
func (s *Store) Update(ctx context.Context, key *store.APIKey) error {
	scopesJSON, err := json.Marshal(key.Scopes)
	if err != nil {
		return err
	}

	permsJSON, err := json.Marshal(key.Permissions)
	if err != nil {
		return err
	}

	metaJSON, err := json.Marshal(key.Metadata)
	if err != nil {
		return err
	}

	query := `
		UPDATE auth_api_keys
		SET name = $1, scopes = $2, permissions = $3, metadata = $4,
		    expires_at = $5, revoked_at = $6, updated_at = $7
		WHERE id = $8
	`
	res, err := s.db.ExecContext(ctx, query,
		key.Name,
		string(scopesJSON),
		string(permsJSON),
		string(metaJSON),
		key.ExpiresAt,
		key.RevokedAt,
		key.UpdatedAt,
		key.ID,
	)
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

// Revoke sets revoked_at timestamp on the key.
func (s *Store) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	query := `
		UPDATE auth_api_keys
		SET revoked_at = $1, updated_at = $1
		WHERE id = $2
	`
	res, err := s.db.ExecContext(ctx, query, revokedAt, id)
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

// TouchLastUsed updates last used telemetry.
func (s *Store) TouchLastUsed(ctx context.Context, id string, at time.Time, ip string, ua string) error {
	query := `
		UPDATE auth_api_keys
		SET last_used_at = $1, last_used_ip = $2, last_used_ua = $3, updated_at = $1
		WHERE id = $4
	`
	res, err := s.db.ExecContext(ctx, query, at, ip, ua, id)
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

// List queries keys matching filter criteria.
func (s *Store) List(ctx context.Context, filter store.ListFilter) ([]*store.APIKey, error) {
	var sb strings.Builder
	sb.WriteString(`
		SELECT id, name, prefix, key_hash, user_id, organization_id, service_id,
		       scopes, permissions, metadata, expires_at, revoked_at,
		       last_used_at, last_used_ip, last_used_ua, created_at, updated_at
		FROM auth_api_keys
		WHERE 1=1
	`)

	var args []any
	argIdx := 1

	if filter.UserID != "" {
		sb.WriteString(" AND user_id = $" + strconv.Itoa(argIdx))
		args = append(args, filter.UserID)
		argIdx++
	}
	if filter.OrganizationID != "" {
		sb.WriteString(" AND organization_id = $" + strconv.Itoa(argIdx))
		args = append(args, filter.OrganizationID)
		argIdx++
	}
	if filter.ServiceID != "" {
		sb.WriteString(" AND service_id = $" + strconv.Itoa(argIdx))
		args = append(args, filter.ServiceID)
		argIdx++
	}
	if !filter.IncludeRevoked {
		sb.WriteString(" AND revoked_at IS NULL")
	}

	sb.WriteString(" ORDER BY created_at DESC")

	if filter.Limit > 0 {
		sb.WriteString(" LIMIT $" + strconv.Itoa(argIdx))
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		sb.WriteString(" OFFSET $" + strconv.Itoa(argIdx))
		args = append(args, filter.Offset)
		argIdx++
	}

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*store.APIKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, k)
	}
	return results, rows.Err()
}

// Delete permanently removes an API key.
func (s *Store) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_api_keys WHERE id = $1`
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

// DeleteExpired removes keys that expired prior to the cutoff timestamp.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	query := `DELETE FROM auth_api_keys WHERE expires_at IS NOT NULL AND expires_at < $1`
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanKey(scanner rowScanner) (*store.APIKey, error) {
	var (
		k          store.APIKey
		userID     sql.NullString
		orgID      sql.NullString
		serviceID  sql.NullString
		scopesRaw  sql.NullString
		permsRaw   sql.NullString
		metaRaw    sql.NullString
		lastUsedIP sql.NullString
		lastUsedUA sql.NullString
	)

	err := scanner.Scan(
		&k.ID,
		&k.Name,
		&k.Prefix,
		&k.KeyHash,
		&userID,
		&orgID,
		&serviceID,
		&scopesRaw,
		&permsRaw,
		&metaRaw,
		&k.ExpiresAt,
		&k.RevokedAt,
		&k.LastUsedAt,
		&lastUsedIP,
		&lastUsedUA,
		&k.CreatedAt,
		&k.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		k.UserID = userID.String
	}
	if orgID.Valid {
		k.OrganizationID = orgID.String
	}
	if serviceID.Valid {
		k.ServiceID = serviceID.String
	}
	if lastUsedIP.Valid {
		k.LastUsedIP = lastUsedIP.String
	}
	if lastUsedUA.Valid {
		k.LastUsedUA = lastUsedUA.String
	}

	if scopesRaw.Valid && scopesRaw.String != "" {
		_ = json.Unmarshal([]byte(scopesRaw.String), &k.Scopes)
	}
	if permsRaw.Valid && permsRaw.String != "" {
		_ = json.Unmarshal([]byte(permsRaw.String), &k.Permissions)
	}
	if metaRaw.Valid && metaRaw.String != "" {
		_ = json.Unmarshal([]byte(metaRaw.String), &k.Metadata)
	}

	return &k, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, sql.ErrNoRows) &&
		(strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "unique constraint"))
}
