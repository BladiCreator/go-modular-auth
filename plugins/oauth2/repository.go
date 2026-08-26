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
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOAuth2Repository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormOAuth2Repository) FindClientByClientID(ctx context.Context, clientID string) (*oauth2.OAuthClient, error) {
//		var c oauth2.OAuthClient
//		if err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, oauth2.ErrClientNotFound
//			}
//			return nil, err
//		}
//		return &c, nil
//	}
//
// # Storage and Caching Recommendation (Token Introspection & Authorization Code Cache):
//
// Access Tokens and Authorization Codes can be cached in Redis to achieve high-throughput introspection:
//
//  1. Authorization Codes (`ConsumeAuthorizationCode`):
//     Store ephemeral codes in Redis (`oauth:code:<code>`) with short TTL. Use `GETDEL` for single-use consumption.
//
//  2. Access Token Introspection (`FindAccessToken`):
//     Cache active token hashes in Redis (`oauth:token:<hash>`) with TTL equal to token remaining lifetime.
//
// Recommended Caching Decorator Example:
//
//	type CachedOAuth2Repository struct {
//		dbRepo oauth2.Repository
//		redis  *redis.Client
//	}
//
//	func (r *CachedOAuth2Repository) FindAccessToken(ctx context.Context, tokenHash string) (*oauth2.OAuthAccessToken, error) {
//		val, err := r.redis.Get(ctx, "oauth:token:"+tokenHash).Bytes()
//		if err == nil {
//			var token oauth2.OAuthAccessToken
//			if json.Unmarshal(val, &token) == nil {
//				return &token, nil // Fast Introspection Cache Hit
//			}
//		}
//		token, err := r.dbRepo.FindAccessToken(ctx, tokenHash)
//		if err == nil {
//			bytes, _ := json.Marshal(token)
//			ttl := time.Until(token.ExpiresAt)
//			r.redis.Set(ctx, "oauth:token:"+tokenHash, bytes, ttl)
//		}
//		return token, err
//	}
type Repository interface {
	// FindClientByClientID retrieves an OAuth client by its public ClientID string.
	//
	// Function:
	//   Called during authorize, token exchange, client auth, and introspection endpoints.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached by client_id in Redis/memory.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: Public client_id string.
	//
	// Returns:
	//   - *OAuthClient: Matching client entity if found.
	//   - error: ErrClientNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at FROM oauth_clients WHERE client_id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "oauth:client:" + clientID).Bytes()
	FindClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error)

	// FindClientByID retrieves an OAuth client by its primary database record ID.
	//
	// Function:
	//   Used in administrative client management panels.
	//
	// Storage:
	//   Database (GORM / SQL) - Client primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Primary key record ID.
	//
	// Returns:
	//   - *OAuthClient: Matching client entity.
	//   - error: ErrClientNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at FROM oauth_clients WHERE id = $1 LIMIT 1;
	FindClientByID(ctx context.Context, id string) (*OAuthClient, error)

	// ListClientsByUserID retrieves all OAuth clients owned/registered by a specific user.
	//
	// Function:
	//   Used in user settings UI to display user-created OAuth applications.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - []*OAuthClient: Slice of client entities.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at FROM oauth_clients WHERE user_id = $1;
	ListClientsByUserID(ctx context.Context, userID string) ([]*OAuthClient, error)

	// CreateClient persists a newly registered OAuth client.
	//
	// Function:
	//   Called during dynamic client registration or administrative application onboarding.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational insert.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - client: OAuthClient entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO oauth_clients (id, client_id, client_secret, name, redirect_uris, grant_types, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	CreateClient(ctx context.Context, client *OAuthClient) error

	// UpdateClient updates mutable fields of an existing OAuth client.
	//
	// Function:
	//   Called when updating client settings, redirect URIs, or secret keys.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - client: Modified OAuthClient entity.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE oauth_clients SET name = $1, redirect_uris = $2, grant_types = $3, updated_at = $4 WHERE client_id = $5;
	UpdateClient(ctx context.Context, client *OAuthClient) error

	// DeleteClient removes an OAuth client record from storage by its client_id.
	//
	// Function:
	//   Called when unregistering an OAuth application.
	//
	// Storage:
	//   Database (GORM / SQL) - Record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: Public client ID string.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM oauth_clients WHERE client_id = $1;
	DeleteClient(ctx context.Context, clientID string) error

	// CreateAuthorizationCode persists a single-use authorization code record.
	//
	// Function:
	//   Called at the completion of the interactive authorization code flow.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived authorization code state.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - code: OAuthAuthorizationCode entity containing code secret, PKCE challenge, and scopes.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   INSERT INTO oauth_codes (id, code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "oauth:code:" + code.Code, bytes, ttl).Err()
	CreateAuthorizationCode(ctx context.Context, code *OAuthAuthorizationCode) error

	// ConsumeAuthorizationCode atomically finds and removes (or marks consumed) an authorization code in a single step.
	// This atomic operation guarantees anti-replay protection and race condition prevention.
	//
	// Function:
	//   Called during authorization_code token exchange.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete single-use code consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - code: Raw code secret string.
	//
	// Returns:
	//   - *OAuthAuthorizationCode: Consumed authorization code record.
	//   - error: ErrInvalidAuthorizationCode if missing or expired.
	//
	// Example SQL:
	//   DELETE FROM oauth_codes WHERE code = $1 AND expires_at > $2 RETURNING id, code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "oauth:code:" + code).Bytes()
	ConsumeAuthorizationCode(ctx context.Context, code string) (*OAuthAuthorizationCode, error)

	// CreateAccessToken persists an issued access token.
	//
	// Function:
	//   Called during token generation in token endpoints.
	//
	// Storage:
	//   Database (GORM / SQL) - Token persistence.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: OAuthAccessToken entity containing hashed token, client ID, user ID, scopes, and expiry.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   INSERT INTO oauth_access_tokens (id, token_hash, client_id, user_id, scope, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateAccessToken(ctx context.Context, token *OAuthAccessToken) error

	// FindAccessToken retrieves an access token record by its token hash.
	//
	// Function:
	//   Called during RFC 7662 Introspection or API bearer authorization validation.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached in Redis (`oauth:token:<tokenHash>`) for fast token validation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokenHash: SHA-256 hash of the bearer token string.
	//
	// Returns:
	//   - *OAuthAccessToken: Matching token record if found.
	//   - error: ErrInvalidAccessToken if missing or expired.
	//
	// Example SQL:
	//   SELECT id, token_hash, client_id, user_id, scope, expires_at, created_at FROM oauth_access_tokens WHERE token_hash = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "oauth:token:" + tokenHash).Bytes()
	FindAccessToken(ctx context.Context, tokenHash string) (*OAuthAccessToken, error)

	// DeleteAccessToken removes an access token from storage upon revocation or expiration.
	//
	// Function:
	//   Called during RFC 7009 token revocation.
	//
	// Storage:
	//   Database (GORM / SQL) - Token revocation deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokenHash: Token hash.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM oauth_access_tokens WHERE token_hash = $1;
	DeleteAccessToken(ctx context.Context, tokenHash string) error

	// CreateRefreshToken persists an issued refresh token with its family ID.
	//
	// Function:
	//   Called during token issuance for offline_access grants.
	//
	// Storage:
	//   Database (GORM / SQL) - Refresh token record insertion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: OAuthRefreshToken entity containing token hash, family ID, and revocation state.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   INSERT INTO oauth_refresh_tokens (id, token_hash, family_id, client_id, user_id, scope, revoked, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	CreateRefreshToken(ctx context.Context, token *OAuthRefreshToken) error

	// FindRefreshToken retrieves a refresh token record by its token hash.
	//
	// Function:
	//   Called during refresh_token grant type token renewal.
	//
	// Storage:
	//   Database (GORM / SQL) - Refresh token query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokenHash: SHA-256 hash of the refresh token.
	//
	// Returns:
	//   - *OAuthRefreshToken: Refresh token entity if valid.
	//   - error: ErrInvalidRefreshToken if missing or expired, ErrRefreshTokenRevoked if revoked.
	//
	// Example SQL:
	//   SELECT id, token_hash, family_id, client_id, user_id, scope, revoked, expires_at, created_at FROM oauth_refresh_tokens WHERE token_hash = $1 LIMIT 1;
	FindRefreshToken(ctx context.Context, tokenHash string) (*OAuthRefreshToken, error)

	// DeleteRefreshToken removes a single refresh token from storage.
	//
	// Function:
	//   Called when consuming a refresh token during rotation.
	//
	// Storage:
	//   Database (GORM / SQL) - Single refresh token deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokenHash: Token hash.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM oauth_refresh_tokens WHERE token_hash = $1;
	DeleteRefreshToken(ctx context.Context, tokenHash string) error

	// RevokeRefreshTokenFamily invalidates all refresh tokens and associated access tokens in a token family.
	//
	// Function:
	//   Called when refresh token reuse is detected (detecting token theft attack).
	//
	// Storage:
	//   Database (GORM / SQL) - Token family revocation update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - familyID: Token family identifier string.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE oauth_refresh_tokens SET revoked = true WHERE family_id = $1;
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error

	// FindConsent retrieves user consent granted to a client application.
	//
	// Function:
	//   Used during authorize request to check if user has previously approved scopes.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent record query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - clientID: Target client ID.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - *OAuthConsent: Matching consent entity if found.
	//   - error: ErrConsentRequired if not consented.
	//
	// Example SQL:
	//   SELECT id, client_id, user_id, scopes, created_at, updated_at FROM oauth_consents WHERE client_id = $1 AND user_id = $2 LIMIT 1;
	FindConsent(ctx context.Context, clientID, userID string) (*OAuthConsent, error)

	// ListConsentsByUserID retrieves all active consents granted by a specific user.
	//
	// Function:
	//   Used in user security settings panel to show connected applications.
	//
	// Storage:
	//   Database (GORM / SQL) - User consents list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - []*OAuthConsent: Slice of consents.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, client_id, user_id, scopes, created_at, updated_at FROM oauth_consents WHERE user_id = $1;
	ListConsentsByUserID(ctx context.Context, userID string) ([]*OAuthConsent, error)

	// CreateConsent records a newly granted user consent.
	//
	// Function:
	//   Called after user approves authorization prompt.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent entity creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - consent: OAuthConsent entity.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   INSERT INTO oauth_consents (id, client_id, user_id, scopes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateConsent(ctx context.Context, consent *OAuthConsent) error

	// UpdateConsent updates the granted scopes of an existing consent.
	//
	// Function:
	//   Called when user grants additional scopes to an already authorized app.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent scopes update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - consent: Modified OAuthConsent entity.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE oauth_consents SET scopes = $1, updated_at = $2 WHERE id = $3;
	UpdateConsent(ctx context.Context, consent *OAuthConsent) error

	// DeleteConsent revokes and removes a user consent record.
	//
	// Function:
	//   Called when a user disconnects an authorized application.
	//
	// Storage:
	//   Database (GORM / SQL) - Consent deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Primary key record ID.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM oauth_consents WHERE id = $1;
	DeleteConsent(ctx context.Context, id string) error

	// FindUserByID retrieves a user domain entity by user ID.
	//
	// Function:
	//   Used during UserInfo endpoint processing or authorization prompt rendering.
	//
	// Storage:
	//   Database (GORM / SQL) - User entity lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrInvalidClient/ErrUserNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	FindUserByID(ctx context.Context, userID string) (*entity.User, error)

	// FindSessionByID retrieves an active session domain entity by session ID.
	//
	// Function:
	//   Used during authorize prompt check or RP-Initiated Logout.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Session retrieval by ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sessionID: Session identifier.
	//
	// Returns:
	//   - *entity.Session: Active session entity if found.
	//   - error: ErrLoginRequired if missing or expired.
	//
	// Example SQL:
	//   SELECT id, user_id, token, expires_at, created_at, updated_at FROM sessions WHERE id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:" + sessionID).Bytes()
	FindSessionByID(ctx context.Context, sessionID string) (*entity.Session, error)

	// DeleteSessionByID deletes a session upon RP-Initiated Logout.
	//
	// Function:
	//   Called during OpenID Connect end-session logout endpoint.
	//
	// Storage:
	//   Database (GORM / SQL) - Session deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sessionID: Session identifier.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE id = $1;
	DeleteSessionByID(ctx context.Context, sessionID string) error
}
