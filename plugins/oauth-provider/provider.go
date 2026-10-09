package oauthprovider

import "context"

// OAuthProvider is the strongly typed capability interface exposed by the OAuth 2.1 Provider plugin.
// Applications access it via:
//
//	provider, err := auth.Get[plugins.OAuthProvider](engine)
//	// or
//	provider, err := auth.Get[oauthprovider.OAuthProvider](engine)
type OAuthProvider interface {
	// RegisterClient registers a new OAuth 2.1 client application.
	RegisterClient(ctx context.Context, in RegisterClientInput) (*RegisterClientOutput, error)

	// GetClient retrieves client metadata by client ID.
	GetClient(ctx context.Context, id string) (*Client, error)

	// RevokeClient revokes a client, deactivating it and invalidating its active tokens.
	RevokeClient(ctx context.Context, id string) error

	// Authorize performs the OAuth 2.1 authorization step, validating redirect URIs, scopes,
	// PKCE parameters, and issuing an authorization code after user consent.
	Authorize(ctx context.Context, in AuthorizeInput) (*AuthorizeOutput, error)

	// Token handles the OAuth 2.1 token endpoint (authorization_code, client_credentials, refresh_token),
	// enforcing PKCE, single-use code consumption, and refresh token rotation.
	Token(ctx context.Context, in TokenInput) (*TokenOutput, error)

	// RevokeToken implements RFC 7009 token revocation.
	RevokeToken(ctx context.Context, in RevokeTokenInput) error

	// IntrospectToken implements RFC 7662 token introspection.
	IntrospectToken(ctx context.Context, in IntrospectTokenInput) (*IntrospectTokenOutput, error)
}
