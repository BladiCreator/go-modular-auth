package apikey

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

var (
	// ErrKeyNotFound is returned when an API Key record cannot be located in storage.
	ErrKeyNotFound = errors.New("apikey: key not found")

	// ErrKeyDisabled is returned when attempting to authenticate with a disabled API Key.
	ErrKeyDisabled = errors.New("apikey: key is disabled")

	// ErrKeyExpired is returned when the API Key has passed its expiration timestamp.
	ErrKeyExpired = errors.New("apikey: key has expired")

	// ErrUsageExceeded is returned when the remaining request quota reached zero.
	ErrUsageExceeded = errors.New("apikey: request quota exceeded")

	// ErrRateLimitExceeded is returned when request rate exceeds allowed max requests in the time window.
	ErrRateLimitExceeded = errors.New("apikey: rate limit exceeded")

	// ErrInvalidPrefix is returned when a provided key prefix does not match allowed format.
	ErrInvalidPrefix = errors.New("apikey: invalid key prefix")

	// ErrInvalidName is returned when key name is invalid or empty when required.
	ErrInvalidName = errors.New("apikey: invalid key name")

	// ErrUnauthorized is returned when required scope permissions are missing.
	ErrUnauthorized = errors.New("apikey: unauthorized scope permissions")
)

// Repository defines the storage contract for persisting and retrieving API Key records.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, Redis).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormApiKeyRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormApiKeyRepository) FindApiKeyByKeyHash(ctx context.Context, keyHash string) (*apikey.ApiKey, error) {
//		var k apikey.ApiKey
//		if err := r.db.WithContext(ctx).Where("key_hash = ?", keyHash).First(&k).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, apikey.ErrKeyNotFound
//			}
//			return nil, err
//		}
//		return &k, nil
//	}
//
// # Storage and Caching Pattern (Decorator / Cache-Aside Strategy)
//
// To achieve high-throughput, low-latency API Key verification during HTTP requests,
// implementations are strongly encouraged to decorate the underlying database repository
// with a fast in-memory or Redis caching layer.
//
// Recommended Caching Architecture:
//
//  1. Write-Through / Cache-Aside on FindApiKeyByKeyHash:
//     When `VerifyKey` computes `keyHash`, query a fast cache (e.g. Redis key `apikey:hash:<keyHash>`).
//     If found (Cache Hit), return cached `*ApiKey` immediately.
//     If cache miss, query persistent DB, write to cache with appropriate TTL, and return.
//
//  2. Invalidating Cache on UpdateApiKey / DeleteApiKey:
//     Upon key updating or deletion, evict `apikey:hash:<keyHash>` and `apikey:id:<id>` from cache.
//
//  3. Asynchronous Counter Flush (DeferUpdates):
//     When `DeferUpdates` option is enabled, usage statistics (`RequestCount`, `Remaining`, `LastRequest`)
//     can be updated asynchronously without blocking the caller's execution.
type Repository interface {
	// CreateApiKey persists a new API Key record in storage.
	//
	// Function:
	//   Called during API Key creation endpoint.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational persistence for API Key entity.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - apiKey: ApiKey entity containing key hash, prefix, scopes, rate limits, and owner reference.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO api_keys (id, config_id, name, prefix, key_hash, start, reference_id, enabled, rate_limit_enabled, rate_limit_time_window, rate_limit_max_requests, request_count, remaining, expires_at, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
	CreateApiKey(ctx context.Context, apiKey *ApiKey) error

	// FindApiKeyByID retrieves an API Key by its unique primary key ID.
	//
	// Function:
	//   Used during administrative API Key lookup, updating, or revocation.
	//
	// Storage:
	//   Database (GORM / SQL) - Record lookup by primary key ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique primary key record ID.
	//
	// Returns:
	//   - *ApiKey: Matching API Key entity if found.
	//   - error: ErrKeyNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, config_id, name, prefix, key_hash, start, reference_id, enabled, rate_limit_enabled, request_count, remaining, expires_at, created_at, updated_at FROM api_keys WHERE id = $1 LIMIT 1;
	FindApiKeyByID(ctx context.Context, id string) (*ApiKey, error)

	// FindApiKeyByKeyHash retrieves an API Key by matching its stored SHA-256 key hash string.
	//
	// Function:
	//   Called during API Key verification on incoming HTTP requests.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Cached in Redis/Memory (`apikey:hash:<keyHash>`) to avoid DB load on every request.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - keyHash: Hex-encoded SHA-256 hash of the submitted API key secret.
	//
	// Returns:
	//   - *ApiKey: Matching API Key entity if found.
	//   - error: ErrKeyNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, config_id, name, prefix, key_hash, start, reference_id, enabled, rate_limit_enabled, request_count, remaining, expires_at, created_at, updated_at FROM api_keys WHERE key_hash = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "apikey:hash:" + keyHash).Bytes()
	FindApiKeyByKeyHash(ctx context.Context, keyHash string) (*ApiKey, error)

	// UpdateApiKey updates an existing API Key record's metadata, status, or quota attributes.
	//
	// Function:
	//   Called after verifying a key to update request counts, remaining quota, and last request timestamp.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational record update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - apiKey: Modified ApiKey entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE api_keys SET request_count = $1, remaining = $2, last_request = $3, updated_at = $4 WHERE id = $5;
	UpdateApiKey(ctx context.Context, apiKey *ApiKey) error

	// DeleteApiKey permanently removes an API Key record by ID.
	//
	// Function:
	//   Called when an owner or admin revokes an API Key.
	//
	// Storage:
	//   Database (GORM / SQL) - Persistent record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Primary key record ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM api_keys WHERE id = $1;
	DeleteApiKey(ctx context.Context, id string) error

	// ListApiKeysByReferenceID retrieves paginated API Keys belonging to a given owner reference ID.
	//
	// Function:
	//   Used in developer settings UI to display active API Keys for a user or organization.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational paginated query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - configID: Configuration context identifier.
	//   - referenceID: Owner identifier (e.g. userID or orgID).
	//   - limit: Max records per page.
	//   - offset: Pagination offset.
	//
	// Returns:
	//   - []*ApiKey: Slice of API Key records.
	//   - int64: Total matching record count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, config_id, name, prefix, key_hash, start, reference_id, enabled, request_count, remaining, expires_at, created_at, updated_at FROM api_keys WHERE reference_id = $1 LIMIT $2 OFFSET $3;
	ListApiKeysByReferenceID(ctx context.Context, configID string, referenceID string, limit int, offset int) ([]*ApiKey, int64, error)

	// DeleteExpiredApiKeys purges all keys whose expiration date is prior to current time.
	//
	// Function:
	//   Called by automated cleanup crons or maintenance routines.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//
	// Returns:
	//   - int64: Count of deleted keys.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at <= $1;
	DeleteExpiredApiKeys(ctx context.Context) (int64, error)

	// GetUserByID fetches user details for populating user identity context during authentication.
	//
	// Function:
	//   Used when auto-populating user context after verifying an API Key owned by a user.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational user entity lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: Nil if optional or missing user, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}
