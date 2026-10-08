package oauth

import (
	"context"

	"github.com/BladiCreator/go-modular-auth-oauth/provider"
	"github.com/BladiCreator/go-modular-auth/account"
)

// OAuth is the strongly typed capability provided by the OAuth plugin.
// Applications and transport adapters retrieve this capability via:
//
//	oauthAuth, err := auth.Get[plugins.OAuth]()
//	// or
//	oauthAuth := auth.MustGet[plugins.OAuth]()
type OAuth interface {
	// BeginAuth initiates an OAuth authorization code flow for sign-in or account registration.
	// It validates the redirect URI, generates state and PKCE verifier, persists state, and returns the authorization URL.
	BeginAuth(ctx context.Context, in BeginAuthInput) (*BeginAuthResult, error)

	// BeginLink initiates an OAuth authorization code flow specifically for linking a provider to an existing authenticated user.
	// The user ID is bound to the state session to prevent CSRF and session confusion.
	BeginLink(ctx context.Context, in BeginLinkInput) (*BeginAuthResult, error)

	// CompleteAuth completes the OAuth flow: atomically consumes state, exchanges authorization code for tokens,
	// fetches provider profile, creates or locates the user and Core Account, and creates an active Core Session.
	CompleteAuth(ctx context.Context, in CompleteAuthInput) (*AuthResult, error)

	// CompleteLink completes an explicit account linking flow for the user bound during BeginLink.
	CompleteLink(ctx context.Context, in CompleteLinkInput) (*LinkResult, error)

	// UnlinkAccount removes the link between a user and an OAuth provider.
	// Fails with ErrCannotUnlinkSoleAuthMethod if this is the user's sole authentication method and orphaning is disabled.
	UnlinkAccount(ctx context.Context, userID, provider string) error

	// ListAccounts returns all external OAuth accounts linked to the user.
	ListAccounts(ctx context.Context, userID string) ([]*account.Account, error)

	// GetProvider returns a registered provider by name.
	GetProvider(name string) (provider.Provider, error)

	// PurgeExpired cleans up expired states from the store.
	PurgeExpired(ctx context.Context) (int, error)
}
