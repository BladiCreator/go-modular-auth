// Package postgres provides a production-grade PostgreSQL implementation of GoModularAuth store.Store.
//
// It enforces the "Store = Source of Truth" architectural invariant, handling SQL schemas,
// transactional isolation, and error mapping (mapping SQL uniqueness violations to store.ErrConflict
// and missing rows to store.ErrNotFound).
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

// SchemaDDL defines the core PostgreSQL database schema.
const SchemaDDL = `
CREATE TABLE IF NOT EXISTS auth_users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_accounts (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_auth_accounts_provider UNIQUE(provider, provider_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_accounts_user_id ON auth_accounts(user_id);

CREATE TABLE IF NOT EXISTS auth_credentials (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    account_id VARCHAR(64) NOT NULL REFERENCES auth_accounts(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    secret TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_credentials_account ON auth_credentials(account_id, type);
CREATE INDEX IF NOT EXISTS idx_auth_credentials_user ON auth_credentials(user_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_hash ON auth_sessions(token_hash);

CREATE TABLE IF NOT EXISTS auth_verification_tokens (
    id VARCHAR(64) PRIMARY KEY,
    purpose VARCHAR(64) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_lookup ON auth_verification_tokens(purpose, subject);
`

type txKey struct{}

// DBTX abstracts *sql.DB and *sql.Tx.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store is a PostgreSQL-backed implementation of store.Store.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New creates a new PostgreSQL store adapter.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// DB returns the underlying sql.DB pool.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Migrate applies the foundational authentication schema DDL.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, SchemaDDL)
	return err
}

func (s *Store) dbtx(ctx context.Context) DBTX {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

// Transaction runs fn inside an atomic database transaction.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	txCtx := context.WithValue(ctx, txKey{}, tx)
	if err := fn(txCtx); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) Users() store.UserStore             { return &userStore{s} }
func (s *Store) Accounts() store.AccountStore       { return &accountStore{s} }
func (s *Store) Credentials() store.CredentialStore { return &credentialStore{s} }
func (s *Store) Sessions() store.SessionStore       { return &sessionStore{s} }
func (s *Store) Tokens() store.TokenStore           { return &tokenStore{s} }

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "unique constraint") ||
		strings.Contains(errMsg, "duplicate key") ||
		strings.Contains(errMsg, "23505") {
		return fmt.Errorf("%w: %v", store.ErrConflict, err)
	}
	return err
}

// --- UserStore ---

type userStore struct{ s *Store }

func (us *userStore) Create(ctx context.Context, u *user.User) error {
	query := `INSERT INTO auth_users (id, email, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := us.s.dbtx(ctx).ExecContext(ctx, query, u.ID, u.Email, u.EmailVerified, u.CreatedAt, u.UpdatedAt)
	return mapErr(err)
}

func (us *userStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	query := `SELECT id, email, email_verified, created_at, updated_at FROM auth_users WHERE id = $1`
	var u user.User
	err := us.s.dbtx(ctx).QueryRowContext(ctx, query, id).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (us *userStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	query := `SELECT id, email, email_verified, created_at, updated_at FROM auth_users WHERE email = $1`
	var u user.User
	err := us.s.dbtx(ctx).QueryRowContext(ctx, query, email).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (us *userStore) Update(ctx context.Context, u *user.User) error {
	query := `UPDATE auth_users SET email = $1, email_verified = $2, updated_at = $3 WHERE id = $4`
	res, err := us.s.dbtx(ctx).ExecContext(ctx, query, u.Email, u.EmailVerified, u.UpdatedAt, u.ID)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (us *userStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_users WHERE id = $1`
	res, err := us.s.dbtx(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- AccountStore ---

type accountStore struct{ s *Store }

func (as *accountStore) Create(ctx context.Context, a *account.Account) error {
	query := `INSERT INTO auth_accounts (id, user_id, provider, provider_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := as.s.dbtx(ctx).ExecContext(ctx, query, a.ID, a.UserID, a.Provider, a.ProviderID, a.CreatedAt, a.UpdatedAt)
	return mapErr(err)
}

func (as *accountStore) GetByID(ctx context.Context, id string) (*account.Account, error) {
	query := `SELECT id, user_id, provider, provider_id, created_at, updated_at FROM auth_accounts WHERE id = $1`
	var a account.Account
	err := as.s.dbtx(ctx).QueryRowContext(ctx, query, id).Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

func (as *accountStore) GetByProvider(ctx context.Context, provider, providerID string) (*account.Account, error) {
	query := `SELECT id, user_id, provider, provider_id, created_at, updated_at FROM auth_accounts WHERE provider = $1 AND provider_id = $2`
	var a account.Account
	err := as.s.dbtx(ctx).QueryRowContext(ctx, query, provider, providerID).Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

func (as *accountStore) ListByUser(ctx context.Context, userID string) ([]*account.Account, error) {
	query := `SELECT id, user_id, provider, provider_id, created_at, updated_at FROM auth_accounts WHERE user_id = $1 ORDER BY created_at ASC`
	rows, err := as.s.dbtx(ctx).QueryContext(ctx, query, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var list []*account.Account
	for rows.Next() {
		var a account.Account
		if err := rows.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderID, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, &a)
	}
	return list, rows.Err()
}

func (as *accountStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_accounts WHERE id = $1`
	res, err := as.s.dbtx(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- CredentialStore ---

type credentialStore struct{ s *Store }

func (cs *credentialStore) Create(ctx context.Context, c *credential.Credential) error {
	query := `INSERT INTO auth_credentials (id, user_id, account_id, type, secret, created_at, updated_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := cs.s.dbtx(ctx).ExecContext(ctx, query, c.ID, c.UserID, c.AccountID, string(c.Type), c.Secret, c.CreatedAt, c.UpdatedAt, c.RevokedAt)
	return mapErr(err)
}

func (cs *credentialStore) GetByID(ctx context.Context, id string) (*credential.Credential, error) {
	query := `SELECT id, user_id, account_id, type, secret, created_at, updated_at, revoked_at FROM auth_credentials WHERE id = $1`
	var c credential.Credential
	var typ string
	err := cs.s.dbtx(ctx).QueryRowContext(ctx, query, id).Scan(&c.ID, &c.UserID, &c.AccountID, &typ, &c.Secret, &c.CreatedAt, &c.UpdatedAt, &c.RevokedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	c.Type = credential.Type(typ)
	return &c, nil
}

func (cs *credentialStore) GetActiveByAccount(ctx context.Context, accountID string, typ credential.Type) (*credential.Credential, error) {
	query := `SELECT id, user_id, account_id, type, secret, created_at, updated_at, revoked_at FROM auth_credentials WHERE account_id = $1 AND type = $2 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`
	var c credential.Credential
	var t string
	err := cs.s.dbtx(ctx).QueryRowContext(ctx, query, accountID, string(typ)).Scan(&c.ID, &c.UserID, &c.AccountID, &t, &c.Secret, &c.CreatedAt, &c.UpdatedAt, &c.RevokedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	c.Type = credential.Type(t)
	return &c, nil
}

func (cs *credentialStore) ListByUser(ctx context.Context, userID string) ([]*credential.Credential, error) {
	query := `SELECT id, user_id, account_id, type, secret, created_at, updated_at, revoked_at FROM auth_credentials WHERE user_id = $1 ORDER BY created_at ASC`
	rows, err := cs.s.dbtx(ctx).QueryContext(ctx, query, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var list []*credential.Credential
	for rows.Next() {
		var c credential.Credential
		var t string
		if err := rows.Scan(&c.ID, &c.UserID, &c.AccountID, &t, &c.Secret, &c.CreatedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		c.Type = credential.Type(t)
		list = append(list, &c)
	}
	return list, rows.Err()
}

func (cs *credentialStore) Update(ctx context.Context, c *credential.Credential) error {
	query := `UPDATE auth_credentials SET secret = $1, updated_at = $2, revoked_at = $3 WHERE id = $4`
	res, err := cs.s.dbtx(ctx).ExecContext(ctx, query, c.Secret, c.UpdatedAt, c.RevokedAt, c.ID)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (cs *credentialStore) Revoke(ctx context.Context, id string, now time.Time) error {
	query := `UPDATE auth_credentials SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`
	res, err := cs.s.dbtx(ctx).ExecContext(ctx, query, now, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- SessionStore ---

type sessionStore struct{ s *Store }

func (ss *sessionStore) Create(ctx context.Context, s *session.Session) error {
	query := `INSERT INTO auth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := ss.s.dbtx(ctx).ExecContext(ctx, query, s.ID, s.UserID, s.TokenHash, s.IPAddress, s.UserAgent, s.ExpiresAt, s.RevokedAt, s.CreatedAt)
	return mapErr(err)
}

func (ss *sessionStore) GetByID(ctx context.Context, id string) (*session.Session, error) {
	query := `SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, created_at FROM auth_sessions WHERE id = $1`
	var s session.Session
	err := ss.s.dbtx(ctx).QueryRowContext(ctx, query, id).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &s, nil
}

func (ss *sessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	query := `SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, created_at FROM auth_sessions WHERE token_hash = $1`
	var s session.Session
	err := ss.s.dbtx(ctx).QueryRowContext(ctx, query, tokenHash).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &s, nil
}

func (ss *sessionStore) ListByUser(ctx context.Context, userID string) ([]*session.Session, error) {
	query := `SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, created_at FROM auth_sessions WHERE user_id = $1 ORDER BY created_at DESC`
	rows, err := ss.s.dbtx(ctx).QueryContext(ctx, query, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var list []*session.Session
	for rows.Next() {
		var s session.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, &s)
	}
	return list, rows.Err()
}

func (ss *sessionStore) Revoke(ctx context.Context, id string, now time.Time) error {
	query := `UPDATE auth_sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`
	res, err := ss.s.dbtx(ctx).ExecContext(ctx, query, now, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (ss *sessionStore) RevokeByUser(ctx context.Context, userID string, now time.Time) ([]*session.Session, error) {
	query := `UPDATE auth_sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL RETURNING id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, created_at`
	rows, err := ss.s.dbtx(ctx).QueryContext(ctx, query, now, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var list []*session.Session
	for rows.Next() {
		var s session.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, &s)
	}
	return list, rows.Err()
}

func (ss *sessionStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	query := `DELETE FROM auth_sessions WHERE expires_at <= $1`
	res, err := ss.s.dbtx(ctx).ExecContext(ctx, query, now)
	if err != nil {
		return 0, mapErr(err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- TokenStore ---

type tokenStore struct{ s *Store }

func (ts *tokenStore) Create(ctx context.Context, t *verification.Token) error {
	query := `INSERT INTO auth_verification_tokens (id, purpose, subject, token_hash, expires_at, used_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := ts.s.dbtx(ctx).ExecContext(ctx, query, t.ID, string(t.Purpose), t.Subject, t.TokenHash, t.ExpiresAt, t.UsedAt, t.CreatedAt)
	return mapErr(err)
}

func (ts *tokenStore) GetByHash(ctx context.Context, tokenHash string) (*verification.Token, error) {
	query := `SELECT id, purpose, subject, token_hash, expires_at, used_at, created_at FROM auth_verification_tokens WHERE token_hash = $1`
	var t verification.Token
	var p string
	err := ts.s.dbtx(ctx).QueryRowContext(ctx, query, tokenHash).Scan(&t.ID, &p, &t.Subject, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	t.Purpose = verification.Purpose(p)
	return &t, nil
}

func (ts *tokenStore) MarkUsed(ctx context.Context, id string, now time.Time) error {
	query := `UPDATE auth_verification_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL`
	res, err := ts.s.dbtx(ctx).ExecContext(ctx, query, now, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		var exists bool
		chkQuery := `SELECT TRUE FROM auth_verification_tokens WHERE id = $1`
		if errChk := ts.s.dbtx(ctx).QueryRowContext(ctx, chkQuery, id).Scan(&exists); errChk == nil {
			return store.ErrConflict
		}
		return store.ErrNotFound
	}
	return nil
}

func (ts *tokenStore) DeleteBySubject(ctx context.Context, purpose verification.Purpose, subject string) error {
	query := `DELETE FROM auth_verification_tokens WHERE purpose = $1 AND subject = $2`
	_, err := ts.s.dbtx(ctx).ExecContext(ctx, query, string(purpose), subject)
	return mapErr(err)
}

func (ts *tokenStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	query := `DELETE FROM auth_verification_tokens WHERE expires_at <= $1`
	res, err := ts.s.dbtx(ctx).ExecContext(ctx, query, now)
	if err != nil {
		return 0, mapErr(err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
