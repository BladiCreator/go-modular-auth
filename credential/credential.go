// Package credential defines the Credential entity: the material used to
// prove an identity (password hash, passkey public key, API key hash, ...).
package credential

import "time"

// Type identifies the kind of credential material.
type Type string

// TypePassword is the credential type for password hashes managed by the core.
// Plugins define their own types (e.g. "passkey", "api_key", "recovery_code").
const TypePassword Type = "password"

// Credential is authentication material bound to an account.
//
// Secret never holds plaintext secrets: for passwords it stores the encoded
// hash produced by password.Hasher; plugins must apply equivalent care.
type Credential struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	AccountID string     `json:"account_id"`
	Type      Type       `json:"type"`
	Secret    string     `json:"secret"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the credential has not been revoked.
func (c *Credential) Active() bool {
	return c.RevokedAt == nil
}
