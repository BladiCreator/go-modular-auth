package bearer

import (
	"slices"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// DefaultTokenTTL defines the default duration before a newly issued bearer token expires.
const DefaultTokenTTL = 30 * 24 * time.Hour

// TokenInfo represents the public, safe metadata of a bearer token.
// The plaintext token secret and its cryptographic hash are never exposed.
type TokenInfo struct {
	// ID is the unique random identifier for this token record.
	ID string `json:"id"`

	// Subject represents the authenticated identity (e.g. User ID, Service Account ID).
	Subject string `json:"subject"`

	// PrincipalType classifies the identity type (e.g. auth.PrincipalUser, auth.PrincipalServiceAccount).
	PrincipalType auth.PrincipalType `json:"principal_type"`

	// Scopes lists the authorization scopes granted to this token.
	Scopes []string `json:"scopes"`

	// Metadata holds arbitrary key-value application properties attached to the token.
	Metadata map[string]string `json:"metadata,omitempty"`

	// ExpiresAt is the timestamp at which this token becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// RevokedAt is the timestamp when this token was revoked, or nil if active.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// CreatedAt is the timestamp when the token was issued.
	CreatedAt time.Time `json:"created_at"`
}

// Expired reports whether the token has expired relative to the given time.
func (t *TokenInfo) Expired(now time.Time) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(t.ExpiresAt)
}

// Revoked reports whether the token has been revoked.
func (t *TokenInfo) Revoked() bool {
	return t.RevokedAt != nil
}

// Active reports whether the token is neither expired nor revoked.
func (t *TokenInfo) Active(now time.Time) bool {
	return !t.Revoked() && !t.Expired(now)
}

// HasScope reports whether the token grants the specified scope.
func (t *TokenInfo) HasScope(scope string) bool {
	return slices.Contains(t.Scopes, scope)
}

// HasScopes reports whether the token grants all required scopes.
func (t *TokenInfo) HasScopes(required ...string) bool {
	for _, req := range required {
		if !t.HasScope(req) {
			return false
		}
	}
	return true
}

// Principal converts the token's subject and principal type into a core auth.Principal.
func (t *TokenInfo) Principal() auth.Principal {
	pType := t.PrincipalType
	if pType == "" {
		pType = auth.PrincipalUser
	}
	return auth.Principal{
		Subject: t.Subject,
		Type:    pType,
	}
}

// IssueInput specifies the parameters for generating and persisting a new bearer token.
type IssueInput struct {
	// Subject identifies the owner/principal of the token (required).
	Subject string `json:"subject"`

	// PrincipalType classifies the identity (optional; defaults to auth.PrincipalUser).
	PrincipalType auth.PrincipalType `json:"principal_type,omitempty"`

	// Scopes defines the authorization permissions granted to this token (optional).
	Scopes []string `json:"scopes,omitempty"`

	// TTL specifies the token lifespan. If zero or negative, Config.DefaultTTL is used.
	TTL time.Duration `json:"ttl,omitempty"`

	// Metadata attaches custom key-value attributes (optional).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IssueResult contains the generated plaintext token and its associated metadata.
// The plaintext token is returned ONLY ONCE upon creation and cannot be retrieved later.
type IssueResult struct {
	// Token is the raw, opaque secret bearer token to provide to the client.
	Token string `json:"token"`

	// Info contains the persisted non-sensitive token metadata.
	Info *TokenInfo `json:"info"`
}

// AuthenticateInput encapsulates the transport-neutral credentials for authentication.
type AuthenticateInput struct {
	// Token is the raw bearer token supplied by the caller/client.
	Token string `json:"token"`

	// RequiredScopes is a list of scopes that MUST be granted by the token.
	// If any required scope is missing, authentication fails with ErrInsufficientScope.
	RequiredScopes []string `json:"required_scopes,omitempty"`
}

// AuthResult is the result of a successful bearer token authentication.
type AuthResult struct {
	// Principal is the core GoModularAuth authenticated identity.
	Principal auth.Principal `json:"principal"`

	// Token provides the metadata of the authenticated token (excluding secrets).
	Token *TokenInfo `json:"token"`
}
