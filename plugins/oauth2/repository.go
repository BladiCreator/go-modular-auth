package oauth2

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel error definitions for OAuth 2.1 and OpenID Connect flows.
var (
	// ErrClientNotFound is returned when an OAuth client cannot be found in storage.
	ErrClientNotFound = errors.New("oauth2: client not found")

	// ErrClientDisabled is returned when an OAuth client has been administratively disabled.
	ErrClientDisabled = errors.New("oauth2: client is disabled")

	// ErrInvalidClient is returned when client credentials (ID or secret) are invalid or mismatched.
	ErrInvalidClient = errors.New("oauth2: invalid client credentials")

	// ErrInvalidClientSecret is returned when the provided client secret does not match the stored secret.
	ErrInvalidClientSecret = errors.New("oauth2: invalid client secret")

	// ErrInvalidRedirectURI is returned when the redirect_uri does not match any registered URI for the client.
	ErrInvalidRedirectURI = errors.New("oauth2: invalid or unregistered redirect_uri")

	// ErrInvalidResponseType is returned when response_type is not supported (OAuth 2.1 requires 'code').
	ErrInvalidResponseType = errors.New("oauth2: unsupported response_type (must be 'code')")

	// ErrInvalidGrantType is returned when grant_type is unsupported or not permitted for the client.
	ErrInvalidGrantType = errors.New("oauth2: unsupported or unauthorized grant_type")

	// ErrInvalidAuthorizationCode is returned when the authorization code is invalid, already consumed, or not found.
	ErrInvalidAuthorizationCode = errors.New("oauth2: invalid or already consumed authorization code")

	// ErrAuthorizationCodeExpired is returned when the authorization code has exceeded its validity lifetime.
	ErrAuthorizationCodeExpired = errors.New("oauth2: authorization code has expired")

	// ErrInvalidPKCE is returned when code_verifier is missing or fails SHA-256 S256 comparison against code_challenge.
	ErrInvalidPKCE = errors.New("oauth2: invalid code_verifier or failed PKCE verification")

	// ErrInvalidCodeChallengeMethod is returned when code_challenge_method is not 'S256' (OAuth 2.1 disallows 'plain').
	ErrInvalidCodeChallengeMethod = errors.New("oauth2: only 'S256' code_challenge_method is supported in OAuth 2.1")

	// ErrInvalidRefreshToken is returned when a refresh token cannot be found or is expired.
	ErrInvalidRefreshToken = errors.New("oauth2: invalid or expired refresh token")

	// ErrRefreshTokenRevoked is returned when an already revoked refresh token is presented (potential token theft).
	ErrRefreshTokenRevoked = errors.New("oauth2: refresh token has been revoked")

	// ErrInvalidAccessToken is returned when an access token cannot be validated or is expired/revoked.
	ErrInvalidAccessToken = errors.New("oauth2: invalid or expired access token")

	// ErrConsentRequired is returned in prompt=none when the user has not pre-consented to the requested scopes.
	ErrConsentRequired = errors.New("oauth2: consent required")

	// ErrLoginRequired is returned in prompt=none when the user is not actively authenticated.
	ErrLoginRequired = errors.New("oauth2: login required")

	// ErrAccessDenied is returned when the resource owner or authorization server denied the request.
	ErrAccessDenied = errors.New("oauth2: access denied")

	// ErrInvalidScope is returned when the requested scope is malformed or exceeds authorized client scopes.
	ErrInvalidScope = errors.New("oauth2: requested scope is invalid or exceeds client permissions")

	// ErrInvalidRequest is returned when required parameters are missing or malformed.
	ErrInvalidRequest = errors.New("oauth2: invalid request parameters")

	// ErrUnauthorizedClient is returned when the client is not authorized to use the requested grant type.
	ErrUnauthorizedClient = errors.New("oauth2: client is not authorized to use this grant type")

	// ErrDynamicRegistrationDisabled is returned when dynamic client registration is disabled by configuration.
	ErrDynamicRegistrationDisabled = errors.New("oauth2: dynamic client registration is disabled")

	// ErrInvalidSignature is returned when an HMAC query signature on interactive redirects fails verification.
	ErrInvalidSignature = errors.New("oauth2: invalid interactive query signature")
)

// Repository defines the storage contract required by the OAuth 2.1 Provider plugin.
type Repository interface {
	// FindClientByClientID retrieves an OAuth client by its public ClientID string.
	FindClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error)

	// FindClientByID retrieves an OAuth client by its primary database record ID.
	FindClientByID(ctx context.Context, id string) (*OAuthClient, error)

	// ListClientsByUserID retrieves all OAuth clients owned/registered by a specific user.
	ListClientsByUserID(ctx context.Context, userID string) ([]*OAuthClient, error)

	// CreateClient persists a newly registered OAuth client.
	CreateClient(ctx context.Context, client *OAuthClient) error

	// UpdateClient updates mutable fields of an existing OAuth client.
	UpdateClient(ctx context.Context, client *OAuthClient) error

	// DeleteClient removes an OAuth client record from storage by its client_id.
	DeleteClient(ctx context.Context, clientID string) error

	// CreateAuthorizationCode persists a single-use authorization code record.
	CreateAuthorizationCode(ctx context.Context, code *OAuthAuthorizationCode) error

	// ConsumeAuthorizationCode atomically finds and removes (or marks consumed) an authorization code in a single step.
	// This atomic operation guarantees anti-replay protection and race condition prevention.
	ConsumeAuthorizationCode(ctx context.Context, code string) (*OAuthAuthorizationCode, error)

	// CreateAccessToken persists an issued access token.
	CreateAccessToken(ctx context.Context, token *OAuthAccessToken) error

	// FindAccessToken retrieves an access token record by its token hash.
	FindAccessToken(ctx context.Context, tokenHash string) (*OAuthAccessToken, error)

	// DeleteAccessToken removes an access token from storage upon revocation or expiration.
	DeleteAccessToken(ctx context.Context, tokenHash string) error

	// CreateRefreshToken persists an issued refresh token with its family ID.
	CreateRefreshToken(ctx context.Context, token *OAuthRefreshToken) error

	// FindRefreshToken retrieves a refresh token record by its token hash.
	FindRefreshToken(ctx context.Context, tokenHash string) (*OAuthRefreshToken, error)

	// DeleteRefreshToken removes a single refresh token from storage.
	DeleteRefreshToken(ctx context.Context, tokenHash string) error

	// RevokeRefreshTokenFamily invalidates all refresh tokens and associated access tokens in a token family.
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error

	// FindConsent retrieves user consent granted to a client application.
	FindConsent(ctx context.Context, clientID, userID string) (*OAuthConsent, error)

	// ListConsentsByUserID retrieves all active consents granted by a specific user.
	ListConsentsByUserID(ctx context.Context, userID string) ([]*OAuthConsent, error)

	// CreateConsent records a newly granted user consent.
	CreateConsent(ctx context.Context, consent *OAuthConsent) error

	// UpdateConsent updates the granted scopes of an existing consent.
	UpdateConsent(ctx context.Context, consent *OAuthConsent) error

	// DeleteConsent revokes and removes a user consent record.
	DeleteConsent(ctx context.Context, id string) error

	// FindUserByID retrieves a user domain entity by user ID.
	FindUserByID(ctx context.Context, userID string) (*entity.User, error)

	// FindSessionByID retrieves an active session domain entity by session ID.
	FindSessionByID(ctx context.Context, sessionID string) (*entity.Session, error)

	// DeleteSessionByID deletes a session upon RP-Initiated Logout.
	DeleteSessionByID(ctx context.Context, sessionID string) error
}
