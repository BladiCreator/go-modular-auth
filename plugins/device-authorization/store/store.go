// Package store defines the persistence contract for OAuth 2.0 Device Authorization state in GoModularAuth.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested device authorization grant does not exist.
	ErrNotFound = errors.New("device auth store: grant not found")

	// ErrConflict indicates a uniqueness constraint violation (e.g. duplicate user_code or device_code_hash).
	ErrConflict = errors.New("device auth store: grant conflict")
)

// DeviceStatus represents the lifecycle state of a device authorization grant.
type DeviceStatus string

const (
	// StatusPending indicates the authorization request is awaiting user interaction.
	StatusPending DeviceStatus = "pending"

	// StatusAuthorized indicates the user approved the request, ready for device token exchange.
	StatusAuthorized DeviceStatus = "authorized"

	// StatusDenied indicates the user rejected the authorization request.
	StatusDenied DeviceStatus = "denied"

	// StatusConsumed indicates the device code has been exchanged for credentials (single-use fulfilled).
	StatusConsumed DeviceStatus = "consumed"
)

// DeviceGrant represents the authoritative state of an RFC 8628 device authorization session.
type DeviceGrant struct {
	ID              string            `json:"id"`
	ClientID        string            `json:"client_id"`
	DeviceCodeHash  string            `json:"device_code_hash"`
	UserCode        string            `json:"user_code"`
	Status          DeviceStatus      `json:"status"`
	UserID          string            `json:"user_id,omitempty"`
	Scope           string            `json:"scope,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastPolledAt    *time.Time        `json:"last_polled_at,omitempty"`
	PollingInterval int               `json:"polling_interval"`
	FailedAttempts  int               `json:"failed_attempts"`
	AuthorizedAt    *time.Time        `json:"authorized_at,omitempty"`
	ConsumedAt      *time.Time        `json:"consumed_at,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// Expired reports whether the device grant has passed its validity window.
func (g *DeviceGrant) Expired(now time.Time) bool {
	return g != nil && !now.Before(g.ExpiresAt)
}

// Store defines the persistent storage contract required by the device-authorization plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormDeviceAuthStore struct {
//		db *gorm.DB
//	}
//
//	func (s *GormDeviceAuthStore) GetByDeviceCodeHash(ctx context.Context, codeHash string) (*store.DeviceGrant, error) {
//		var grant store.DeviceGrant
//		if err := s.db.WithContext(ctx).Where("device_code_hash = ?", codeHash).First(&grant).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, store.ErrNotFound
//			}
//			return nil, err
//		}
//		return &grant, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Device authorization polling is a high-frequency operation while awaiting user approval.
// To offload repeated lookups while preserving Store as authoritative truth, rate limit
// tracking and polling throttles may be layered with Redis:
//
//	type CachedDeviceAuthStore struct {
//		dbStore store.Store
//		redis   *redis.Client
//		ttl     time.Duration
//	}
//
//	func (s *CachedDeviceAuthStore) GetByDeviceCodeHash(ctx context.Context, codeHash string) (*store.DeviceGrant, error) {
//		// Authoritative store remains database of record; cache must not bypass state transitions
//		return s.dbStore.GetByDeviceCodeHash(ctx, codeHash)
//	}
type Store interface {
	// Transaction executes fn atomically within an isolated transaction.
	//
	// Function:
	//   Guarantees atomic single-use redemption and state transitions to prevent replay attacks.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - fn: Transaction function callback.
	//
	// Returns:
	//   - error: Nil on commit, or error causing rollback.
	//
	// Example SQL:
	//   BEGIN; ... COMMIT;
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error

	// Create persists a newly initiated device authorization request.
	//
	// Function:
	//   Invoked during Device Authorization Request initiation (RFC 8628 section 3.1).
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - grant: New device authorization record.
	//
	// Returns:
	//   - error: ErrConflict if user_code or device_code_hash already exists, or infrastructure error.
	//
	// Example SQL:
	//   INSERT INTO auth_device_grants (id, client_id, device_code_hash, user_code, status, user_id, scope, metadata, expires_at, last_polled_at, polling_interval, failed_attempts, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
	Create(ctx context.Context, grant *DeviceGrant) error

	// GetByDeviceCodeHash retrieves an active device grant using the SHA-256 hash of device_code.
	//
	// Function:
	//   Invoked on every device polling request (RFC 8628 section 3.4).
	//
	// Storage:
	//   Database (GORM / SQL) - Indexed by device_code_hash.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - codeHash: Hexadecimal SHA-256 hash of the device code.
	//
	// Returns:
	//   - *store.DeviceGrant: Found record.
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, client_id, device_code_hash, user_code, status, user_id, scope, metadata, expires_at, last_polled_at, polling_interval, failed_attempts, authorized_at, consumed_at, created_at, updated_at FROM auth_device_grants WHERE device_code_hash = $1 LIMIT 1;
	GetByDeviceCodeHash(ctx context.Context, codeHash string) (*DeviceGrant, error)

	// GetByUserCode retrieves a device grant by the user-facing verification code.
	//
	// Function:
	//   Invoked when the end user enters the code on the web verification page (RFC 8628 section 3.3).
	//
	// Storage:
	//   Database (GORM / SQL) - Indexed by user_code.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userCode: Normalized uppercase user code.
	//
	// Returns:
	//   - *store.DeviceGrant: Found record.
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, client_id, device_code_hash, user_code, status, user_id, scope, metadata, expires_at, last_polled_at, polling_interval, failed_attempts, authorized_at, consumed_at, created_at, updated_at FROM auth_device_grants WHERE user_code = $1 LIMIT 1;
	GetByUserCode(ctx context.Context, userCode string) (*DeviceGrant, error)

	// Update modifies mutable grant properties such as status, user_id, last_polled_at, and polling_interval.
	//
	// Function:
	//   Invoked during polling rate updates, user authorization/denial, and final token consumption.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - grant: Updated grant record.
	//
	// Returns:
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_device_grants SET status = $1, user_id = $2, last_polled_at = $3, polling_interval = $4, failed_attempts = $5, authorized_at = $6, consumed_at = $7, updated_at = $8 WHERE id = $9;
	Update(ctx context.Context, grant *DeviceGrant) error

	// IncrementFailedAttempts increments the bad attempt counter for a user code and returns the new count.
	//
	// Function:
	//   Invoked when an invalid or wrong code is submitted to prevent brute-force attacks.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userCode: Target user code.
	//
	// Returns:
	//   - int: Updated count of failed attempts.
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_device_grants SET failed_attempts = failed_attempts + 1, updated_at = $1 WHERE user_code = $2 RETURNING failed_attempts;
	IncrementFailedAttempts(ctx context.Context, userCode string) (int, error)

	// Delete removes a device authorization record by ID.
	//
	// Function:
	//   Invoked during explicit revocation or teardown.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Primary key identifier.
	//
	// Returns:
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_device_grants WHERE id = $1;
	Delete(ctx context.Context, id string) error

	// DeleteExpired purges all grants expired before the specified instant.
	//
	// Function:
	//   Invoked by scheduled maintenance routines to clean up abandoned requests.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - before: Expiration cutoff timestamp.
	//
	// Returns:
	//   - int: Number of deleted rows.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_device_grants WHERE expires_at < $1;
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
