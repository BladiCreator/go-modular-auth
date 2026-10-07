// Package store defines the persistence contracts of GoModularAuth.
//
// The Store is the source of truth for authentication state. Store adapters
// (PostgreSQL, MySQL, SQLite, memory, ...) implement these interfaces and own
// SQL, schemas, indexes, migrations and engine-specific errors. The core owns
// authentication rules: validation, expiration, revocation and workflows.
//
// Adapters must translate engine errors into the sentinels of this package
// (ErrNotFound, ErrConflict) so the core can reason about them.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

var (
	// ErrNotFound is returned when the requested record does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a uniqueness constraint or a conditional
	// update (e.g. consuming an already used token) fails.
	ErrConflict = errors.New("store: conflict")
)

// Store aggregates the core stores and provides transactions.
type Store interface {
	Users() UserStore
	Accounts() AccountStore
	Credentials() CredentialStore
	Sessions() SessionStore
	Tokens() TokenStore

	// Transaction runs fn atomically. Store operations invoked with the ctx
	// passed to fn must participate in the transaction. Returning an error
	// from fn rolls back. Nested calls must join the outer transaction.
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// UserStore persists users. Email uniqueness must be enforced (ErrConflict).
type UserStore interface {
	Create(ctx context.Context, u *user.User) error
	GetByID(ctx context.Context, id string) (*user.User, error)
	GetByEmail(ctx context.Context, email string) (*user.User, error)
	Update(ctx context.Context, u *user.User) error
	Delete(ctx context.Context, id string) error
}

// AccountStore persists accounts. (Provider, ProviderID) must be unique (ErrConflict).
type AccountStore interface {
	Create(ctx context.Context, a *account.Account) error
	GetByID(ctx context.Context, id string) (*account.Account, error)
	GetByProvider(ctx context.Context, provider, providerID string) (*account.Account, error)
	ListByUser(ctx context.Context, userID string) ([]*account.Account, error)
	Delete(ctx context.Context, id string) error
}

// CredentialStore persists credentials.
type CredentialStore interface {
	Create(ctx context.Context, c *credential.Credential) error
	GetByID(ctx context.Context, id string) (*credential.Credential, error)
	// GetActiveByAccount returns the non revoked credential of the given type for an account.
	GetActiveByAccount(ctx context.Context, accountID string, t credential.Type) (*credential.Credential, error)
	ListByUser(ctx context.Context, userID string) ([]*credential.Credential, error)
	Update(ctx context.Context, c *credential.Credential) error
	Revoke(ctx context.Context, id string, at time.Time) error
}

// SessionStore persists sessions by token hash. TokenHash must be unique.
type SessionStore interface {
	Create(ctx context.Context, s *session.Session) error
	GetByID(ctx context.Context, id string) (*session.Session, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*session.Session, error)
	ListByUser(ctx context.Context, userID string) ([]*session.Session, error)
	Revoke(ctx context.Context, id string, at time.Time) error
	// RevokeByUser revokes every active session of a user and returns the
	// revoked sessions so callers can invalidate derived caches.
	RevokeByUser(ctx context.Context, userID string, at time.Time) ([]*session.Session, error)
	// DeleteExpired removes sessions expired before the given instant.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// TokenStore persists verification tokens.
type TokenStore interface {
	Create(ctx context.Context, t *verification.Token) error
	GetByHash(ctx context.Context, tokenHash string) (*verification.Token, error)
	// MarkUsed atomically sets UsedAt only if the token is still unused
	// (e.g. UPDATE ... WHERE used_at IS NULL). It returns ErrConflict when the
	// token was already consumed, guaranteeing single-use semantics.
	MarkUsed(ctx context.Context, id string, at time.Time) error
	// DeleteBySubject removes every token of a purpose issued to a subject.
	DeleteBySubject(ctx context.Context, purpose verification.Purpose, subject string) error
	// DeleteExpired removes tokens expired before the given instant.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
