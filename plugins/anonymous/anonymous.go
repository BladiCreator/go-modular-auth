// Package anonymous provides anonymous authentication identities and lifecycle management
// with optional conversion and account linking to permanent authenticated users for GoModularAuth.
package anonymous

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth-anonymous/store"
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// ProviderAnonymous is the Core account provider name recorded when creating anonymous accounts.
const ProviderAnonymous = "anonymous"

// PrincipalAnonymous is the principal type classifying an authenticated anonymous user.
// Authorization policies and middleware should inspect this to deny anonymous users access
// to privileged operations reserved for permanent users.
const PrincipalAnonymous auth.PrincipalType = "anonymous"

// Identity is an alias to store.Identity exposing the anonymous identity model in the public package.
type Identity = store.Identity

// AuthenticateInput holds options for creating an anonymous identity and session.
type AuthenticateInput struct {
	// Session carries optional IPAddress and UserAgent recorded on the newly created server session.
	Session auth.SessionOptions

	// Metadata carries optional application-specific key-value pairs stored with the anonymous identity.
	Metadata map[string]string
}

// AuthResult is the result returned upon successful anonymous authentication.
type AuthResult struct {
	// User is the created GoModularAuth Core user entity.
	User *user.User

	// Session is the created GoModularAuth Core session entity.
	Session *session.Session

	// Token is the plaintext opaque session token returned once to the client.
	Token string

	// Identity is the persistent anonymous identity record.
	Identity *Identity
}

// ConvertInput defines parameters for converting an anonymous user in-place into a permanent user with email and password.
type ConvertInput struct {
	// AnonymousUserID is the Core User ID of the anonymous user.
	AnonymousUserID string

	// AnonymousToken is the optional current session token of the anonymous user.
	// When provided, it validates that the caller actively owns the session before conversion.
	AnonymousToken string

	// Email is the permanent user's email address. Required.
	Email string

	// Password is the permanent user's plaintext password. Required.
	Password string
}

// ConvertAccountInput defines parameters for converting an anonymous user by linking an external/custom provider account (OAuth, passkey, WebAuthn).
type ConvertAccountInput struct {
	// AnonymousUserID is the Core User ID of the anonymous user.
	AnonymousUserID string

	// AnonymousToken is the optional current session token of the anonymous user.
	// When provided, it validates that the caller actively owns the session.
	AnonymousToken string

	// Provider is the external provider name (e.g. "google", "github", "passkey"). Required.
	Provider string

	// ProviderID is the unique user ID within the external provider. Required.
	ProviderID string

	// Email is an optional email address to associate with the user if provided by the external identity.
	Email string
}

// ConvertResult holds the result of a conversion operation.
type ConvertResult struct {
	// User is the updated Core user entity.
	User *user.User

	// Identity is the updated anonymous identity record with ConvertedAt set.
	Identity *Identity
}

// LinkInput defines parameters for linking/merging an anonymous identity into an existing permanent account.
type LinkInput struct {
	// AnonymousUserID is the Core User ID of the anonymous user. Required if AnonymousToken is empty.
	AnonymousUserID string

	// AnonymousToken is the optional session token of the anonymous user.
	// When provided, AnonymousUserID is inferred or verified against this session.
	AnonymousToken string

	// PermanentEmail and PermanentPassword authenticate the target permanent account by password credentials.
	// Alternatively, PermanentToken can be provided.
	PermanentEmail    string
	PermanentPassword string

	// PermanentToken is an active session token of the target permanent user,
	// proving that the caller is already authenticated as the permanent user.
	PermanentToken string

	// RevokeAnonymousSessions specifies whether to revoke all active sessions belonging
	// to the anonymous user upon successful linking. Default is true.
	RevokeAnonymousSessions bool
}

// LinkResult holds the outcome of an account link/merge operation.
type LinkResult struct {
	// AnonymousUserID is the ID of the anonymous user that was linked.
	AnonymousUserID string

	// PermanentUser is the target permanent Core user entity.
	PermanentUser *user.User

	// Identity is the updated anonymous identity record reflecting the link.
	Identity *Identity
}

// CleanupResult summarizes the outcome of a cleanup operation on expired anonymous identities.
type CleanupResult struct {
	// IdentitiesDeleted is the number of expired anonymous identity records deleted from the store.
	IdentitiesDeleted int

	// UsersDeleted is the number of orphaned Core users deleted.
	UsersDeleted int

	// SessionsRevoked is the number of active sessions revoked during cleanup.
	SessionsRevoked int
}

// Anonymous is the strongly typed capability interface exposed by the anonymous plugin module.
// Applications retrieve it using:
//
//	anon, err := auth.Get[plugins.Anonymous]()
//	// or
//	anon, err := auth.Get[anonymous.Anonymous]()
type Anonymous interface {
	// Authenticate creates a new Core User, links an anonymous account, persists an anonymous identity,
	// and issues an authenticated session.
	Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error)

	// GetIdentity retrieves the anonymous identity associated with the given Core User ID.
	// Returns ErrAnonymousNotFound if the user does not have an anonymous record.
	GetIdentity(ctx context.Context, userID string) (*Identity, error)

	// IsAnonymous reports whether the given Core User ID corresponds to an active, unexpired,
	// and unconverted anonymous identity.
	IsAnonymous(ctx context.Context, userID string) (bool, error)

	// Principal returns an auth.Principal for the given user ID.
	// If the user has an active anonymous identity, Principal.Type is PrincipalAnonymous ("anonymous").
	// Otherwise, it returns Principal.Type as auth.PrincipalUser ("user").
	Principal(ctx context.Context, userID string) (auth.Principal, error)

	// Convert converts an active anonymous user in-place to a permanent account with email and password credentials.
	// All existing application relations to the user ID are preserved.
	Convert(ctx context.Context, in ConvertInput) (*ConvertResult, error)

	// ConvertWithAccount converts an active anonymous user by linking an external provider account (e.g. OAuth, passkey).
	ConvertWithAccount(ctx context.Context, in ConvertAccountInput) (*ConvertResult, error)

	// Link merges an anonymous identity into an existing permanent account after validating explicit authentication
	// for the permanent user. It prevents privilege escalation and triggers account link events.
	Link(ctx context.Context, in LinkInput) (*LinkResult, error)

	// Cleanup deletes expired and unconverted anonymous identities and their associated core users and sessions.
	// Passing a zero Time defaults to the current clock time.
	Cleanup(ctx context.Context, before time.Time) (CleanupResult, error)
}
