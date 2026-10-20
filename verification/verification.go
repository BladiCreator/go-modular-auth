// Package verification defines the VerificationToken primitive: a secure,
// expiring, single-use token reusable by the core (email verification,
// password reset) and by plugins (magic link, OTP, one-time token, ...).
package verification

import "time"

// Purpose namespaces tokens so a token issued for one flow can never be
// consumed by another. Plugins should prefix their purposes ("magiclink:login").
type Purpose string

// Core purposes.
const (
	PurposeEmailVerification Purpose = "email_verification"
	PurposePasswordReset     Purpose = "password_reset"
)

// Token is a single-use verification token. Only TokenHash is persisted.
type Token struct {
	ID        string     `json:"id"`
	Purpose   Purpose    `json:"purpose"`
	Subject   string     `json:"subject"`
	TokenHash string     `json:"token_hash"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Used reports whether the token has already been consumed.
func (t *Token) Used() bool {
	return t.UsedAt != nil
}

// Expired reports whether the token is expired at the given instant.
func (t *Token) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}
