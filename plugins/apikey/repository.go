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
//     When `VerifyKey` computes `keyHash`, query an fast cache (e.g. Redis key `apikey:hash:<keyHash>`).
//     If found (Cache Hit), return cached `*ApiKey` immediately ($O(1)$ response).
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
	CreateApiKey(ctx context.Context, apiKey *ApiKey) error

	// FindApiKeyByID retrieves an API Key by its unique primary key ID.
	FindApiKeyByID(ctx context.Context, id string) (*ApiKey, error)

	// FindApiKeyByKeyHash retrieves an API Key by matching its stored SHA-256 key hash (or plain key).
	FindApiKeyByKeyHash(ctx context.Context, keyHash string) (*ApiKey, error)

	// UpdateApiKey updates an existing API Key record's metadata, status, or quota attributes.
	UpdateApiKey(ctx context.Context, apiKey *ApiKey) error

	// DeleteApiKey permanently removes an API Key by ID.
	DeleteApiKey(ctx context.Context, id string) error

	// ListApiKeysByReferenceID retrieves paginated API Keys belonging to a given owner reference ID.
	ListApiKeysByReferenceID(ctx context.Context, configID string, referenceID string, limit int, offset int) ([]*ApiKey, int64, error)

	// DeleteExpiredApiKeys purges all keys whose expiration date is prior to current time.
	DeleteExpiredApiKeys(ctx context.Context) (int64, error)

	// GetUserByID fetches user details for populating user identity context during authentication.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}
