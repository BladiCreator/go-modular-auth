package bearer

import (
	"context"
)

// Bearer is the strongly typed capability provided by the bearer plugin.
// Applications and transport adapters retrieve this capability via:
//
//	bearerAuth, err := auth.Get[plugins.Bearer]()
//	// or
//	bearerAuth := auth.MustGet[plugins.Bearer]()
type Bearer interface {
	// Authenticate validates bearer credentials against persistence (and optional cache),
	// checks expiration, revocation, and scope permissions, and resolves the credentials into a Principal.
	Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error)

	// Issue generates and stores a new cryptographically secure opaque bearer token for the specified subject.
	// The plaintext token is returned strictly once in IssueResult and is never stored in plaintext.
	Issue(ctx context.Context, in IssueInput) (*IssueResult, error)

	// Revoke revokes an individual token by its record ID, immediately invalidating subsequent authentication attempts.
	Revoke(ctx context.Context, tokenID string) error

	// RevokeBySubject revokes all active bearer tokens belonging to the specified subject (e.g., on logout or account compromise).
	RevokeBySubject(ctx context.Context, subject string) error

	// Get retrieves public metadata for a token by its ID.
	// Returns ErrTokenNotFound if not found. Plaintext tokens and hashes are never exposed.
	Get(ctx context.Context, tokenID string) (*TokenInfo, error)

	// ListBySubject retrieves metadata for all tokens belonging to the specified subject.
	ListBySubject(ctx context.Context, subject string) ([]*TokenInfo, error)

	// Delete permanently removes a token record by its ID from persistence and invalidates cache.
	Delete(ctx context.Context, tokenID string) error

	// PurgeExpired removes all expired or revoked tokens from persistence.
	PurgeExpired(ctx context.Context) (int, error)
}
