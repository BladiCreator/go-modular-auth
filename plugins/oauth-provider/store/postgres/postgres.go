// Package postgres provides a PostgreSQL persistence adapter for the OAuth 2.1 Provider.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth-provider/store"
)

// Store implements store.Store backed by PostgreSQL.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL OAuth 2.1 Provider store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Clients() store.ClientStore { return &clientStore{db: s.db} }
func (s *Store) Codes() store.CodeStore     { return &codeStore{db: s.db} }
func (s *Store) Tokens() store.TokenStore   { return &tokenStore{db: s.db} }

func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("oauth_provider postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

// --- ClientStore ---

type clientStore struct{ db *sql.DB }

func (cs *clientStore) Create(ctx context.Context, c *store.Client) error {
	urisJSON, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	grantsJSON, err := json.Marshal(c.AllowedGrantTypes)
	if err != nil {
		return err
	}
	scopesJSON, err := json.Marshal(c.AllowedScopes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO oauth_clients (id, secret_hash, name, client_type, redirect_uris, allowed_grant_types, allowed_scopes, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = cs.db.ExecContext(ctx, query,
		c.ID,
		c.SecretHash,
		c.Name,
		string(c.ClientType),
		string(urisJSON),
		string(grantsJSON),
		string(scopesJSON),
		string(c.Status),
		c.CreatedAt,
		c.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique constraint") {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

func (cs *clientStore) GetByID(ctx context.Context, id string) (*store.Client, error) {
	query := `
		SELECT id, secret_hash, name, client_type, redirect_uris, allowed_grant_types, allowed_scopes, status, created_at, updated_at
		FROM oauth_clients WHERE id = $1
	`
	row := cs.db.QueryRowContext(ctx, query, id)

	var c store.Client
	var secretHash sql.NullString
	var clientType, urisStr, grantsStr, scopesStr, status string

	err := row.Scan(
		&c.ID,
		&secretHash,
		&c.Name,
		&clientType,
		&urisStr,
		&grantsStr,
		&scopesStr,
		&status,
		&c.CreatedAt,
		&c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}

	c.SecretHash = secretHash.String
	c.ClientType = store.ClientType(clientType)
	c.Status = store.ClientStatus(status)
	_ = json.Unmarshal([]byte(urisStr), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(grantsStr), &c.AllowedGrantTypes)
	_ = json.Unmarshal([]byte(scopesStr), &c.AllowedScopes)

	return &c, nil
}

func (cs *clientStore) Update(ctx context.Context, c *store.Client) error {
	urisJSON, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	grantsJSON, err := json.Marshal(c.AllowedGrantTypes)
	if err != nil {
		return err
	}
	scopesJSON, err := json.Marshal(c.AllowedScopes)
	if err != nil {
		return err
	}

	query := `
		UPDATE oauth_clients
		SET secret_hash = $2, name = $3, client_type = $4, redirect_uris = $5, allowed_grant_types = $6, allowed_scopes = $7, status = $8, updated_at = $9
		WHERE id = $1
	`
	res, err := cs.db.ExecContext(ctx, query,
		c.ID,
		c.SecretHash,
		c.Name,
		string(c.ClientType),
		string(urisJSON),
		string(grantsJSON),
		string(scopesJSON),
		string(c.Status),
		c.UpdatedAt,
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

func (cs *clientStore) Revoke(ctx context.Context, id string, now time.Time) error {
	query := `UPDATE oauth_clients SET status = $2, updated_at = $3 WHERE id = $1`
	res, err := cs.db.ExecContext(ctx, query, id, string(store.ClientStatusRevoked), now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (cs *clientStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM oauth_clients WHERE id = $1`
	res, err := cs.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- CodeStore ---

type codeStore struct{ db *sql.DB }

func (cos *codeStore) Create(ctx context.Context, c *store.AuthorizationCode) error {
	scopesJSON, err := json.Marshal(c.Scopes)
	if err != nil {
		return err
	}
	query := `
		INSERT INTO oauth_authorization_codes (id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = cos.db.ExecContext(ctx, query,
		c.ID,
		c.CodeHash,
		c.ClientID,
		c.UserID,
		c.RedirectURI,
		string(scopesJSON),
		c.CodeChallenge,
		c.CodeChallengeMethod,
		c.ExpiresAt,
		c.CreatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique constraint") {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

func (cos *codeStore) GetByHash(ctx context.Context, codeHash string) (*store.AuthorizationCode, error) {
	query := `
		SELECT id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, consumed_at, created_at
		FROM oauth_authorization_codes WHERE code_hash = $1
	`
	row := cos.db.QueryRowContext(ctx, query, codeHash)

	var c store.AuthorizationCode
	var scopesStr string
	var consumedAt sql.NullTime

	err := row.Scan(
		&c.ID,
		&c.CodeHash,
		&c.ClientID,
		&c.UserID,
		&c.RedirectURI,
		&scopesStr,
		&c.CodeChallenge,
		&c.CodeChallengeMethod,
		&c.ExpiresAt,
		&consumedAt,
		&c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if consumedAt.Valid {
		c.ConsumedAt = &consumedAt.Time
	}
	_ = json.Unmarshal([]byte(scopesStr), &c.Scopes)
	return &c, nil
}

func (cos *codeStore) Consume(ctx context.Context, codeHash string, now time.Time) (*store.AuthorizationCode, error) {
	// Atomic consume: only updates if consumed_at is NULL
	query := `
		UPDATE oauth_authorization_codes
		SET consumed_at = $2
		WHERE code_hash = $1 AND consumed_at IS NULL
		RETURNING id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, consumed_at, created_at
	`
	row := cos.db.QueryRowContext(ctx, query, codeHash, now)

	var c store.AuthorizationCode
	var scopesStr string
	var consumedAt sql.NullTime

	err := row.Scan(
		&c.ID,
		&c.CodeHash,
		&c.ClientID,
		&c.UserID,
		&c.RedirectURI,
		&scopesStr,
		&c.CodeChallenge,
		&c.CodeChallengeMethod,
		&c.ExpiresAt,
		&consumedAt,
		&c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Either code does not exist or was already consumed
			return nil, store.ErrConflict
		}
		return nil, err
	}
	if consumedAt.Valid {
		c.ConsumedAt = &consumedAt.Time
	}
	_ = json.Unmarshal([]byte(scopesStr), &c.Scopes)
	return &c, nil
}

func (cos *codeStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	query := `DELETE FROM oauth_authorization_codes WHERE expires_at <= $1`
	res, err := cos.db.ExecContext(ctx, query, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- TokenStore ---

type tokenStore struct{ db *sql.DB }

func (ts *tokenStore) CreateAccessToken(ctx context.Context, t *store.AccessToken) error {
	scopesJSON, err := json.Marshal(t.Scopes)
	if err != nil {
		return err
	}
	query := `
		INSERT INTO oauth_access_tokens (id, token_hash, client_id, user_id, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = ts.db.ExecContext(ctx, query,
		t.ID,
		t.TokenHash,
		t.ClientID,
		t.UserID,
		string(scopesJSON),
		t.ExpiresAt,
		t.CreatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique constraint") {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

func (ts *tokenStore) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*store.AccessToken, error) {
	query := `
		SELECT id, token_hash, client_id, user_id, scopes, expires_at, revoked_at, created_at
		FROM oauth_access_tokens WHERE token_hash = $1
	`
	row := ts.db.QueryRowContext(ctx, query, tokenHash)

	var t store.AccessToken
	var scopesStr string
	var revokedAt sql.NullTime

	err := row.Scan(
		&t.ID,
		&t.TokenHash,
		&t.ClientID,
		&t.UserID,
		&scopesStr,
		&t.ExpiresAt,
		&revokedAt,
		&t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	_ = json.Unmarshal([]byte(scopesStr), &t.Scopes)
	return &t, nil
}

func (ts *tokenStore) RevokeAccessToken(ctx context.Context, tokenHash string, now time.Time) error {
	query := `UPDATE oauth_access_tokens SET revoked_at = $2 WHERE token_hash = $1`
	_, err := ts.db.ExecContext(ctx, query, tokenHash, now)
	return err
}

func (ts *tokenStore) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	scopesJSON, err := json.Marshal(t.Scopes)
	if err != nil {
		return err
	}
	query := `
		INSERT INTO oauth_refresh_tokens (id, token_hash, access_token_id, client_id, user_id, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err = ts.db.ExecContext(ctx, query,
		t.ID,
		t.TokenHash,
		t.AccessTokenID,
		t.ClientID,
		t.UserID,
		string(scopesJSON),
		t.ExpiresAt,
		t.CreatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique constraint") {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

func (ts *tokenStore) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*store.RefreshToken, error) {
	query := `
		SELECT id, token_hash, access_token_id, client_id, user_id, scopes, expires_at, revoked_at, created_at
		FROM oauth_refresh_tokens WHERE token_hash = $1
	`
	row := ts.db.QueryRowContext(ctx, query, tokenHash)

	var t store.RefreshToken
	var scopesStr string
	var revokedAt sql.NullTime

	err := row.Scan(
		&t.ID,
		&t.TokenHash,
		&t.AccessTokenID,
		&t.ClientID,
		&t.UserID,
		&scopesStr,
		&t.ExpiresAt,
		&revokedAt,
		&t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	_ = json.Unmarshal([]byte(scopesStr), &t.Scopes)
	return &t, nil
}

func (ts *tokenStore) RevokeRefreshToken(ctx context.Context, tokenHash string, now time.Time) error {
	query := `UPDATE oauth_refresh_tokens SET revoked_at = $2 WHERE token_hash = $1`
	_, err := ts.db.ExecContext(ctx, query, tokenHash, now)
	return err
}

func (ts *tokenStore) RevokeTokensByClient(ctx context.Context, clientID string, now time.Time) error {
	q1 := `UPDATE oauth_access_tokens SET revoked_at = $2 WHERE client_id = $1 AND revoked_at IS NULL`
	q2 := `UPDATE oauth_refresh_tokens SET revoked_at = $2 WHERE client_id = $1 AND revoked_at IS NULL`
	if _, err := ts.db.ExecContext(ctx, q1, clientID, now); err != nil {
		return err
	}
	_, err := ts.db.ExecContext(ctx, q2, clientID, now)
	return err
}

func (ts *tokenStore) RevokeTokensByUser(ctx context.Context, userID string, now time.Time) error {
	q1 := `UPDATE oauth_access_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`
	q2 := `UPDATE oauth_refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`
	if _, err := ts.db.ExecContext(ctx, q1, userID, now); err != nil {
		return err
	}
	_, err := ts.db.ExecContext(ctx, q2, userID, now)
	return err
}

func (ts *tokenStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	q1 := `DELETE FROM oauth_access_tokens WHERE expires_at <= $1`
	q2 := `DELETE FROM oauth_refresh_tokens WHERE expires_at <= $1`
	res1, _ := ts.db.ExecContext(ctx, q1, now)
	res2, _ := ts.db.ExecContext(ctx, q2, now)

	var n1, n2 int64
	if res1 != nil {
		n1, _ = res1.RowsAffected()
	}
	if res2 != nil {
		n2, _ = res2.RowsAffected()
	}
	return int(n1 + n2), nil
}
