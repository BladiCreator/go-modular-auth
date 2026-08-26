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
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOIDCProviderRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormOIDCProviderRepository) FindByClientID(ctx context.Context, clientID string) (*oidcprovider.OAuthClient, error) {
//		var c oidcprovider.OAuthClient
//		if err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, oidcprovider.ErrInvalidClient
//			}
//			return nil, err
//		}
//		return &c, nil
//	}
//
// # Storage and Caching Recommendation (Token Introspection & Authorization Code Cache):
//
// High-traffic OIDC Provider deployments benefit greatly from caching access tokens and client credentials:
//
//  1. Access Token Introspection (`FindByAccessToken`):
//     Cache access token grants in Redis (`oidc:token:<accessToken>`) with TTL matching `access_token_expires_at`.
//
//  2. Authorization Codes (`ConsumeAuthorizationCode`):
//     Store single-use codes in Redis (`oidc:code:<code>`) and consume via `GETDEL` for single-use replay protection.
//
// Recommended Caching Decorator Example:
//
//	type CachedOIDCProviderRepository struct {
//		dbRepo oidcprovider.Repository
//		redis  *redis.Client
//	}
//
//	func (r *CachedOIDCProviderRepository) FindByAccessToken(ctx context.Context, tokenStr string) (*oidcprovider.OAuthToken, error) {
//		val, err := r.redis.Get(ctx, "oidc:token:"+tokenStr).Bytes()
//		if err == nil {
//			var token oidcprovider.OAuthToken
//			if json.Unmarshal(val, &token) == nil {
//				return &token, nil // Fast Introspection Cache Hit
//			}
//		}
//		token, err := r.dbRepo.FindByAccessToken(ctx, tokenStr)
//		if err == nil {
//			bytes, _ := json.Marshal(token)
//			ttl := time.Until(token.AccessTokenExpiresAt)
//			r.redis.Set(ctx, "oidc:token:"+tokenStr, bytes, ttl)
//		}
//		return token, err
//	}
type Repository interface {
	// CreateClient persists a new OAuth client application in storage.
	//
	// Function:
	//   Used during dynamic client registration or administrative client creation.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational client entity persistence.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - client: The OAuthClient entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO oidc_clients (id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	CreateClient(ctx context.Context, client *OAuthClient) error

	// FindByClientID retrieves an OAuth client application by its public client_id.
	//
	// Function:
	//   Used during authorize, token exchange, userinfo, and client authentication requests.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached by client_id in Redis/memory.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: The unique public OAuth client ID.
	//
	// Returns:
	//   - *OAuthClient: Matching OAuth client entity if found.
	//   - error: ErrInvalidClient if not found, or database error.
	//
	// Example SQL:
	//   SELECT id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at FROM oidc_clients WHERE client_id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "oidc:client:" + clientID).Bytes()
	FindByClientID(ctx context.Context, clientID string) (*OAuthClient, error)

	// UpdateClient updates mutable fields of an existing OAuth client.
	//
	// Function:
	//   Used during administrative client updates or secret rotation.
	//
	// Storage:
	//   Database (GORM / SQL) - Client update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - client: Modified OAuthClient entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE oidc_clients SET name = $1, redirect_uris = $2, grant_types = $3, updated_at = $4 WHERE client_id = $5;
	UpdateClient(ctx context.Context, client *OAuthClient) error

	// DeleteClient removes an OAuth client record from persistent storage by client_id.
	//
	// Function:
	//   Used when unregistering or purging an OAuth client application.
	//
	// Storage:
	//   Database (GORM / SQL) - Client record removal.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: The unique public OAuth client ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM oidc_clients WHERE client_id = $1;
	DeleteClient(ctx context.Context, clientID string) error

	// ListClientsByUserID retrieves all OAuth clients owned/registered by a specific user.
	//
	// Function:
	//   Used in developer portals or user settings to list user-created OAuth applications.
	//
	// Storage:
	//   Database (GORM / SQL) - User client apps query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The unique user identifier.
	//
	// Returns:
	//   - []*OAuthClient: Slice of matching OAuth clients.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at FROM oidc_clients WHERE user_id = $1;
	ListClientsByUserID(ctx context.Context, userID string) ([]*OAuthClient, error)

	// CreateAuthorizationCode persists a new single-use authorization code grant.
	//
	// Function:
	//   Called at the end of the authorization flow after user consent.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived authorization code state.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - code: OAuthCode entity containing code secret, PKCE challenge, and granted scopes.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO oidc_codes (id, code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "oidc:code:" + code.Code, bytes, ttl).Err()
	CreateAuthorizationCode(ctx context.Context, code *OAuthCode) error

	// ConsumeAuthorizationCode atomically retrieves and invalidates/deletes an authorization code record.
	//
	// Function:
	//   Called during authorization_code token exchange to prevent code reuse and replay attacks.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete single-use code consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - code: The authorization code string secret.
	//
	// Returns:
	//   - *OAuthCode: The consumed code grant entity if valid.
	//   - error: ErrInvalidGrant if missing or expired, ErrCodeAlreadyConsumed if reused.
	//
	// Example SQL:
	//   DELETE FROM oidc_codes WHERE code = $1 AND expires_at > $2 RETURNING id, code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "oidc:code:" + code).Bytes()
	ConsumeAuthorizationCode(ctx context.Context, code string) (*OAuthCode, error)

	// DeleteExpiredCodes purges all expired authorization codes from storage.
	//
	// Function:
	//   Called by background cleanup tasks or maintenance crons.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk code deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM oidc_codes WHERE expires_at <= $1;
	DeleteExpiredCodes(ctx context.Context) error

	// CreateTokenPair persists a new access token (and optional refresh token) grant.
	//
	// Function:
	//   Called during token issuance for authorization_code, refresh_token, or client_credentials grants.
	//
	// Storage:
	//   Database (GORM / SQL) - Token pair insertion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: OAuthToken entity containing access_token, refresh_token, and expiration details.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO oidc_tokens (id, access_token, refresh_token, client_id, user_id, scope, access_token_expires_at, refresh_token_expires_at, revoked, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	CreateTokenPair(ctx context.Context, token *OAuthToken) error

	// FindByAccessToken retrieves token details by matching access_token string.
	//
	// Function:
	//   Used during Introspection, UserInfo, or API authorization token validation.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached in Redis (`oidc:token:<accessToken>`) for fast token validation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - accessToken: The raw access token string.
	//
	// Returns:
	//   - *OAuthToken: Matching token grant if found and active.
	//   - error: ErrInvalidGrant if missing, revoked, or expired.
	//
	// Example SQL:
	//   SELECT id, access_token, refresh_token, client_id, user_id, scope, access_token_expires_at, refresh_token_expires_at, revoked, created_at FROM oidc_tokens WHERE access_token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "oidc:token:" + accessToken).Bytes()
	FindByAccessToken(ctx context.Context, accessToken string) (*OAuthToken, error)

	// FindByRefreshToken retrieves token grant details matching a refresh_token string.
	//
	// Function:
	//   Called during refresh_token grant type token renewal.
	//
	// Storage:
	//   Database (GORM / SQL) - Refresh token query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - refreshToken: The raw refresh token string.
	//
	// Returns:
	//   - *OAuthToken: Matching token grant if found and valid.
	//   - error: ErrInvalidGrant if missing or expired, ErrRefreshTokenRevoked if already revoked.
	//
	// Example SQL:
	//   SELECT id, access_token, refresh_token, client_id, user_id, scope, access_token_expires_at, refresh_token_expires_at, revoked, created_at FROM oidc_tokens WHERE refresh_token = $1 LIMIT 1;
	FindByRefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error)

	// RevokeTokenPair marks a specific token grant (by token ID or token string) as revoked.
	//
	// Function:
	//   Called during RFC 7009 Token Revocation or session sign-out.
	//
	// Storage:
	//   Database (GORM / SQL) - Revocation status update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokenID: Primary record ID or token identifier.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE oidc_tokens SET revoked = true WHERE id = $1 OR access_token = $1 OR refresh_token = $1;
	RevokeTokenPair(ctx context.Context, tokenID string) error

	// RevokeTokensByClientIDAndUserID revokes all active token grants issued to a user for a specific client.
	//
	// Function:
	//   Called when a user revokes access to a third-party client application.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk token revocation update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: OAuth client identifier.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE oidc_tokens SET revoked = true WHERE client_id = $1 AND user_id = $2;
	RevokeTokensByClientIDAndUserID(ctx context.Context, clientID, userID string) error

	// DeleteExpiredTokens purges all expired and revoked token records from storage.
	//
	// Function:
	//   Called by maintenance tasks to keep storage size optimal.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk token deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM oidc_tokens WHERE refresh_token_expires_at <= $1 OR (refresh_token IS NULL AND access_token_expires_at <= $1);
	DeleteExpiredTokens(ctx context.Context) error

	// GetConsent retrieves persistent user consent granted to a client application.
	//
	// Function:
	//   Called during interactive authorization to check if prompt=none or remembered consent applies.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent record query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: Target OAuth client ID.
	//   - userID: User identifier.
	//
	// Returns:
	//   - *OAuthConsent: User consent record if found.
	//   - error: ErrConsentRequired if not consented, or database error.
	//
	// Example SQL:
	//   SELECT id, client_id, user_id, scopes, granted_at FROM oidc_consents WHERE client_id = $1 AND user_id = $2 LIMIT 1;
	GetConsent(ctx context.Context, clientID, userID string) (*OAuthConsent, error)

	// SaveConsent creates or updates remembered user consent for a client application.
	//
	// Function:
	//   Called when a user approves scopes during authorization prompt.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent record insertion/upsert.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - consent: OAuthConsent entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO oidc_consents (id, client_id, user_id, scopes, granted_at) VALUES ($1, $2, $3, $4, $5)
	//   ON CONFLICT (client_id, user_id) DO UPDATE SET scopes = $4, granted_at = $5;
	SaveConsent(ctx context.Context, consent *OAuthConsent) error

	// RevokeConsent removes remembered consent granted by a user to a client application.
	//
	// Function:
	//   Called when a user disconnects an authorized application in account settings.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: Target OAuth client ID.
	//   - userID: User identifier.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM oidc_consents WHERE client_id = $1 AND user_id = $2;
	RevokeConsent(ctx context.Context, clientID, userID string) error

	// GetUserByID fetches user profile details to populate UserInfo response claims.
	//
	// Function:
	//   Called during OpenID Connect /userinfo endpoint processing or ID token claim assembly.
	//
	// Storage:
	//   Database (GORM / SQL) - User primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}
