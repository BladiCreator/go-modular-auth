// Package account defines the Account entity: the link between a User and
// an authentication provider (password, google, github, passkey, ...).
package account

import "time"

// ProviderPassword is the provider name used by the core for email/password accounts.
const ProviderPassword = "password"

// Account represents an authentication relationship of a user with a provider.
//
// ProviderID is the identifier of the user inside the provider. For the
// password provider the core uses the user's ID.
type Account struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Provider   string    `json:"provider"`
	ProviderID string    `json:"provider_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
