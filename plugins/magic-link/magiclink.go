package magiclink

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/verification"
)

// Purpose is the verification token purpose used by this plugin.
// Tokens issued with this purpose cannot be consumed by other workflows (password reset, email verification, etc.).
const Purpose verification.Purpose = "magiclink:authenticate"

// AccountProvider is the provider name recorded when auto-creating accounts.
const AccountProvider = "magiclink"

// RequestInput contains parameters for requesting a magic link.
type RequestInput struct {
	// Email is the destination email address. Required.
	Email string

	// Metadata carries optional application context.
	Metadata map[string]string
}

// AuthenticateInput contains parameters for authenticating via a magic link token.
type AuthenticateInput struct {
	// Token is the plaintext single-use token received by the user. Required.
	Token string

	// Session holds optional metadata (IP address, User Agent) recorded with the session.
	Session auth.SessionOptions
}

// MagicLink is the public capability interface exposed by this plugin.
// Applications retrieve it using auth.Get[magiclink.MagicLink](a) or auth.Get[plugins.MagicLink](a).
type MagicLink interface {
	// Request initiates the passwordless authentication flow for the given email address.
	// If the user does not exist and AllowSignUp is false, it returns nil to prevent user enumeration.
	Request(ctx context.Context, in RequestInput) error

	// Authenticate validates and atomically consumes the single-use magic link token,
	// establishes a server-side session, and returns the authentication result.
	Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error)

	// Revoke deletes all active magic link tokens issued for the given email address.
	Revoke(ctx context.Context, email string) error
}

// Capability is an alias for MagicLink to allow idiomatic capability retrieval.
type Capability = MagicLink
