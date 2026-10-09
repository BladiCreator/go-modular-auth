package oidc

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/account"
)

// OIDC is the strongly typed capability provided by the OIDC plugin.
// Applications and transport adapters retrieve this capability via:
//
//	oidcAuth, err := auth.Get[plugins.OIDC](engine)
type OIDC interface {
	// BeginAuth initiates an OpenID Connect authorization code flow with PKCE and Nonce.
	BeginAuth(ctx context.Context, in BeginAuthInput) (*BeginAuthResult, error)

	// BeginLink initiates an OIDC flow specifically for linking a provider to an existing authenticated user.
	BeginLink(ctx context.Context, in BeginLinkInput) (*BeginAuthResult, error)

	// CompleteAuth completes the OIDC flow: atomically consumes state, exchanges code for tokens,
	// cryptographically verifies the ID token, provisions or locates Core User & Account, and issues a Core Session.
	CompleteAuth(ctx context.Context, in CompleteAuthInput) (*AuthResult, error)

	// CompleteLink completes an account linking flow for the user bound during BeginLink.
	CompleteLink(ctx context.Context, in CompleteLinkInput) (*LinkResult, error)

	// UnlinkAccount removes the link between a user and an OIDC provider.
	UnlinkAccount(ctx context.Context, userID, provider string) error

	// ListAccounts returns all external OIDC accounts linked to the user.
	ListAccounts(ctx context.Context, userID string) ([]*account.Account, error)

	// ValidateIDToken cryptographically verifies a raw ID token against the provider's JWKS and issuer rules.
	ValidateIDToken(ctx context.Context, providerID, rawIDToken, expectedNonce string) (*IDTokenClaims, error)

	// GetProvider returns a registered provider configuration.
	GetProvider(providerID string) (*ProviderConfig, error)

	// Discover queries an OpenID Provider's discovery document (.well-known/openid-configuration).
	Discover(ctx context.Context, issuerURL string) (*DiscoveryDocument, error)
}
