package apikey

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// ApiKey represents a secure API Key database record.
type ApiKey struct {
	// ID is the unique record identifier (UUID/cuid).
	ID string `json:"id"`

	// ConfigID identifies the configuration scope (default: "default").
	ConfigID string `json:"configId"`

	// Name is an optional human-readable descriptive label for the API Key.
	Name *string `json:"name,omitempty"`

	// Start contains the initial readable characters of the raw key for UI display (e.g. "sk_live_abc123").
	Start string `json:"start"`

	// Prefix specifies the key prefix (e.g. "sk_live_").
	Prefix string `json:"prefix"`

	// Key holds the stored SHA-256 hash in base64url format (or raw plaintext key if hashing is disabled).
	Key string `json:"key"`

	// ReferenceID identifies the owner entity (e.g., user ID or organization ID).
	ReferenceID string `json:"referenceId"`

	// ReferenceType specifies the type of reference owner ("user" or "organization").
	ReferenceType string `json:"referenceType"`

	// RefillInterval is the auto-refill interval duration in milliseconds (optional).
	RefillInterval *int64 `json:"refillInterval,omitempty"`

	// RefillAmount is the quota amount added during each refill interval (optional).
	RefillAmount *int64 `json:"refillAmount,omitempty"`

	// LastRefillAt is the timestamp when quota refill was last calculated.
	LastRefillAt *time.Time `json:"lastRefillAt,omitempty"`

	// Enabled indicates whether the API Key is active for authentication.
	Enabled bool `json:"enabled"`

	// RateLimitEnabled specifies if rate limiting per time window is active.
	RateLimitEnabled bool `json:"rateLimitEnabled"`

	// RateLimitTimeWindow specifies the rate limit sliding window duration in milliseconds.
	RateLimitTimeWindow *int64 `json:"rateLimitTimeWindow,omitempty"`

	// RateLimitMax specifies the maximum allowed requests within the rate limit window.
	RateLimitMax *int64 `json:"rateLimitMax,omitempty"`

	// RequestCount tracks the number of requests made within the active rate limit window.
	RequestCount int64 `json:"requestCount"`

	// Remaining tracks remaining overall quota usages (nil indicates unlimited usage).
	Remaining *int64 `json:"remaining,omitempty"`

	// LastRequest records the timestamp of the most recent API Key usage.
	LastRequest *time.Time `json:"lastRequest,omitempty"`

	// ExpiresAt specifies when the key expires (nil indicates no expiration).
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// CreatedAt records when the API Key was issued.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt records when the API Key metadata was last updated.
	UpdatedAt time.Time `json:"updatedAt"`

	// Permissions defines granted scope permissions map (e.g. {"users": ["read", "write"]}).
	Permissions map[string][]string `json:"permissions,omitempty"`

	// Metadata holds arbitrary custom JSON attributes associated with the API Key.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CreateApiKeyParams holds input values required to create a new API Key.
type CreateApiKeyParams struct {
	// ConfigID identifies the configuration scope (default: "default").
	ConfigID string `json:"configId,omitempty"`

	// Name optionally labels the key.
	Name *string `json:"name,omitempty"`

	// Prefix customizes key prefix (overrides default config prefix).
	Prefix string `json:"prefix,omitempty"`

	// KeyLength customizes random string length (default: 32).
	KeyLength int `json:"keyLength,omitempty"`

	// ReferenceID specifies the owner identifier (userID or organizationID).
	ReferenceID string `json:"referenceId"`

	// ReferenceType specifies owner entity type ("user" or "organization", default: "user").
	ReferenceType string `json:"referenceType,omitempty"`

	// RefillInterval optionally configures auto refill interval in milliseconds.
	RefillInterval *int64 `json:"refillInterval,omitempty"`

	// RefillAmount optionally configures quota increment for each refill.
	RefillAmount *int64 `json:"refillAmount,omitempty"`

	// RateLimitEnabled enables rate limiting for this key.
	RateLimitEnabled bool `json:"rateLimitEnabled,omitempty"`

	// RateLimitTimeWindow configures rate limit window in milliseconds.
	RateLimitTimeWindow *int64 `json:"rateLimitTimeWindow,omitempty"`

	// RateLimitMax configures max requests per rate limit window.
	RateLimitMax *int64 `json:"rateLimitMax,omitempty"`

	// Remaining sets initial remaining quota (nil = unlimited).
	Remaining *int64 `json:"remaining,omitempty"`

	// ExpiresAt sets optional key expiration time.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// Permissions grants scopes map to this key.
	Permissions map[string][]string `json:"permissions,omitempty"`

	// Metadata adds custom JSON key-value pairs.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CreateApiKeyResult contains the persisted API Key entity and the raw unhashed key.
type CreateApiKeyResult struct {
	// ApiKey is the created entity record (containing hash or metadata).
	ApiKey *ApiKey `json:"apiKey"`

	// RawKey is the plaintext API Key returned ONCE upon creation.
	RawKey string `json:"rawKey"`
}

// VerifyApiKeyParams holds parameters to authenticate an incoming request's API Key.
type VerifyApiKeyParams struct {
	// Key is the raw unhashed API Key string extracted from request header/query.
	Key string `json:"key"`

	// RequiredPermissions optionally specifies required scopes to validate.
	RequiredPermissions map[string][]string `json:"requiredPermissions,omitempty"`
}

// VerifyApiKeyResult contains the outcome of an API Key authentication check.
type VerifyApiKeyResult struct {
	// Valid indicates whether the API key is active, unexpired, and within limits.
	Valid bool `json:"valid"`

	// ApiKey is the retrieved API Key record.
	ApiKey *ApiKey `json:"apiKey,omitempty"`

	// User is the associated user entity (if ReferenceType is "user" and user exists).
	User *entity.User `json:"user,omitempty"`

	// Permissions returns the granted permissions map.
	Permissions map[string][]string `json:"permissions,omitempty"`

	// Error contains a human-readable failure description if Valid is false.
	Error string `json:"error,omitempty"`
}

// GetApiKeyParams specifies input for retrieving a key by ID.
type GetApiKeyParams struct {
	// ID is the unique database record ID.
	ID string `json:"id"`
}

// UpdateApiKeyParams specifies parameters for updating an existing key's parameters.
type UpdateApiKeyParams struct {
	// ID is the target key record ID.
	ID string `json:"id"`

	// Name optionally updates the descriptive label.
	Name *string `json:"name,omitempty"`

	// Enabled optionally activates or deactivates the key.
	Enabled *bool `json:"enabled,omitempty"`

	// RateLimitEnabled optionally toggles rate limiting.
	RateLimitEnabled *bool `json:"rateLimitEnabled,omitempty"`

	// RateLimitTimeWindow optionally updates rate limit sliding window in ms.
	RateLimitTimeWindow *int64 `json:"rateLimitTimeWindow,omitempty"`

	// RateLimitMax optionally updates max allowed requests per window.
	RateLimitMax *int64 `json:"rateLimitMax,omitempty"`

	// Remaining optionally sets total usage quota remaining.
	Remaining *int64 `json:"remaining,omitempty"`

	// RefillInterval optionally updates quota refill interval in ms.
	RefillInterval *int64 `json:"refillInterval,omitempty"`

	// RefillAmount optionally updates quota refill increment.
	RefillAmount *int64 `json:"refillAmount,omitempty"`

	// ExpiresAt optionally updates key expiration timestamp.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// Permissions optionally replaces granted scopes map.
	Permissions map[string][]string `json:"permissions,omitempty"`

	// Metadata optionally replaces JSON metadata map.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// DeleteApiKeyParams specifies parameters for revoking an API Key.
type DeleteApiKeyParams struct {
	// ID is the key record ID to delete.
	ID string `json:"id"`
}

// ListApiKeysParams specifies query filters for listing API Keys.
type ListApiKeysParams struct {
	// ConfigID optionally filters by configuration scope (default: "default").
	ConfigID string `json:"configId,omitempty"`

	// ReferenceID filters keys owned by a specific user or organization ID.
	ReferenceID string `json:"referenceId"`

	// Limit specifies maximum pagination count (default: 20).
	Limit int `json:"limit,omitempty"`

	// Offset specifies pagination starting offset.
	Offset int `json:"offset,omitempty"`
}

// ListApiKeysResult contains paginated API Keys and total count.
type ListApiKeysResult struct {
	// ApiKeys is the slice of matching API Key records.
	ApiKeys []*ApiKey `json:"apiKeys"`

	// Total is the total count of keys matching the reference filter.
	Total int64 `json:"total"`
}
