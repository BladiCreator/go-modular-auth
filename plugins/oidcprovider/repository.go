package oidcprovider

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel errors for the OIDC Provider plugin (RFC 6749 & OpenID Connect Core compliant).
var (
	// ErrInvalidClient is returned when client authentication fails or the client application is disabled.
	ErrInvalidClient = errors.New("invalid_client: client authentication failed or client disabled")

	// ErrInvalidGrant is returned when an authorization code or refresh token is invalid, expired, or revoked.
	ErrInvalidGrant = errors.New("invalid_grant: invalid, expired, or revoked authorization code/refresh token")

	// ErrInvalidRequest is returned when required parameters are missing or malformed.
	ErrInvalidRequest = errors.New("invalid_request: missing or invalid parameters")

	// ErrUnauthorizedClient is returned when the client is not authorized to use the requested grant type.
	ErrUnauthorizedClient = errors.New("unauthorized_client: client is not allowed to use this grant type")

	// ErrUnsupportedGrantType is returned when the requested grant_type is unsupported.
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type: grant type is not supported")

	// ErrInvalidScope is returned when the requested scope is invalid or exceeds granted scope.
	ErrInvalidScope = errors.New("invalid_scope: scope is invalid or not granted")

	// ErrAccessDenied is returned when the resource owner or authorization server denies the request.
	ErrAccessDenied = errors.New("access_denied: resource owner or authorization server denied request")

	// ErrCodeAlreadyConsumed is returned when an authorization code is reused, triggering token revocation.
	ErrCodeAlreadyConsumed = errors.New("invalid_grant: authorization code has already been used")

	// ErrPKCEValidationFailed is returned when code_verifier fails SHA256/plain comparison against code_challenge.
	ErrPKCEValidationFailed = errors.New("invalid_grant: code_verifier does not match code_challenge")

	// ErrUserNotFound is returned when the user associated with a grant or token cannot be found.
	ErrUserNotFound = errors.New("oidcprovider: user not found")

	// ErrConsentRequired is returned when interactive user consent is required before authorization.
	ErrConsentRequired = errors.New("oidcprovider: user consent required")

	// ErrInvalidConsentCode is returned when a consent validation code is invalid or expired.
	ErrInvalidConsentCode = errors.New("oidcprovider: invalid consent code")
)

// Repository defines the persistent storage contract required by the OIDC Provider plugin.
type Repository interface {
	// OAuth Client Management
	CreateClient(ctx context.Context, client *OAuthClient) error
	FindByClientID(ctx context.Context, clientID string) (*OAuthClient, error)
	UpdateClient(ctx context.Context, client *OAuthClient) error
	DeleteClient(ctx context.Context, clientID string) error
	ListClientsByUserID(ctx context.Context, userID string) ([]*OAuthClient, error)

	// Authorization Code Management
	CreateAuthorizationCode(ctx context.Context, code *OAuthCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (*OAuthCode, error)
	DeleteExpiredCodes(ctx context.Context) error

	// Token Pair Management
	CreateTokenPair(ctx context.Context, token *OAuthToken) error
	FindByAccessToken(ctx context.Context, accessToken string) (*OAuthToken, error)
	FindByRefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error)
	RevokeTokenPair(ctx context.Context, tokenID string) error
	RevokeTokensByClientIDAndUserID(ctx context.Context, clientID, userID string) error
	DeleteExpiredTokens(ctx context.Context) error

	// Consent Management
	GetConsent(ctx context.Context, clientID, userID string) (*OAuthConsent, error)
	SaveConsent(ctx context.Context, consent *OAuthConsent) error
	RevokeConsent(ctx context.Context, clientID, userID string) error

	// User Entity Integration
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}
