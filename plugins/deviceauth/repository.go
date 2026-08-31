package deviceauth

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

// Sentinel errors for the Device Authorization plugin.
var (
	// ErrInvalidDeviceCode is returned when a provided device code does not exist in storage.
	ErrInvalidDeviceCode = errors.New("deviceauth: invalid device code")

	// ErrInvalidUserCode is returned when a provided user verification code does not exist in storage.
	ErrInvalidUserCode = errors.New("deviceauth: invalid user verification code")

	// ErrCodeExpired is returned when attempting to exchange or authorize a device code that has passed its expiration time.
	ErrCodeExpired = errors.New("deviceauth: device code has expired")

	// ErrSlowDown is returned when client polling frequency exceeds the configured interval.
	ErrSlowDown = errors.New("deviceauth: polling rate limit exceeded (slow_down)")

	// ErrAuthorizationPending is returned when polling a device code that is still waiting for user approval.
	ErrAuthorizationPending = errors.New("deviceauth: authorization pending")

	// ErrAccessDenied is returned when polling a device code that has been explicitly denied by the user.
	ErrAccessDenied = errors.New("deviceauth: authorization request denied")

	// ErrAlreadyConsumed is returned when attempting to consume a device code that was already exchanged.
	ErrAlreadyConsumed = errors.New("deviceauth: device code has already been consumed")

	// ErrInvalidGrantType is returned when the exchange request grant_type is not "urn:ietf:params:oauth:grant-type:device_code".
	ErrInvalidGrantType = errors.New("deviceauth: invalid grant_type")

	// ErrUserNotFound is returned when the owner user record cannot be found upon token exchange.
	ErrUserNotFound = errors.New("deviceauth: user not found")

	// ErrInvalidClientID is returned when client_id validation fails or mismatch occurs.
	ErrInvalidClientID = errors.New("deviceauth: invalid client_id")

	// ErrInvalidParameter is returned when required parameters are missing or malformed.
	ErrInvalidParameter = errors.New("deviceauth: required parameter is missing or invalid")
)

// Repository defines the persistent storage contract required by the Device Authorization plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormDeviceAuthRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormDeviceAuthRepository) FindByDeviceCode(ctx context.Context, deviceCode string) (*deviceauth.DeviceCode, error) {
//		var dc deviceauth.DeviceCode
//		if err := r.db.WithContext(ctx).Where("device_code = ?", deviceCode).First(&dc).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, deviceauth.ErrInvalidDeviceCode
//			}
//			return nil, err
//		}
//		return &dc, nil
//	}
type Repository interface {
	// CreateDeviceCode persists a new device authorization grant record in storage.
	//
	// Function:
	//   Called during RFC 8628 device authorization initiation (`/device/code`).
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived device code state with expiration TTL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - code: DeviceCode entity containing device_code, user_code, verification_uri, and expiration.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO device_codes (id, device_code, user_code, verification_uri, status, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "device:code:" + code.DeviceCode, bytes, ttl).Err()
	CreateDeviceCode(ctx context.Context, code *DeviceCode) error

	// FindByDeviceCode retrieves an active device code record by its device_code secret.
	//
	// Function:
	//   Used during client polling (`/device/token`) to inspect grant status and rate limits.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Ephemeral device code lookup during client polling.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - deviceCode: Raw device code secret string.
	//
	// Returns:
	//   - *DeviceCode: Matching device code record if found.
	//   - error: ErrInvalidDeviceCode if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, device_code, user_code, status, user_id, last_polled_at, expires_at, created_at FROM device_codes WHERE device_code = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "device:code:" + deviceCode).Bytes()
	FindByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// FindByUserCode retrieves an active device code record by its normalized user_code.
	//
	// Function:
	//   Used when a end-user enters their short user code on the device authorization web page.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Lookup device grant state by user_code string.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userCode: User verification code string (e.g. "WDJB-MJHT").
	//
	// Returns:
	//   - *DeviceCode: Matching device code record if found.
	//   - error: ErrInvalidUserCode if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, device_code, user_code, status, user_id, expires_at, created_at FROM device_codes WHERE user_code = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "device:usercode:" + userCode).Bytes()
	FindByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// UpdateLastPolledAt updates the last_polled_at timestamp for rate limiting checks.
	//
	// Function:
	//   Called during client polling to enforce minimum polling intervals (preventing spam).
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Poll timestamp update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - deviceCode: Target device code secret.
	//   - polledAt: Timestamp of current poll request.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE device_codes SET last_polled_at = $1 WHERE device_code = $2;
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "device:polled:" + deviceCode, polledAt.Unix(), ttl).Err()
	UpdateLastPolledAt(ctx context.Context, deviceCode string, polledAt time.Time) error

	// UpdateStatus updates the status (approved/denied) and optional owner userID for a device code by userCode.
	//
	// Function:
	//   Called when an authenticated user approves or denies the device authorization request.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Grant status approval update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userCode: User verification code string.
	//   - status: StatusApproved or StatusDenied.
	//   - userID: Pointer to approving user ID.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE device_codes SET status = $1, user_id = $2 WHERE user_code = $3;
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "device:status:" + userCode, status, ttl).Err()
	UpdateStatus(ctx context.Context, userCode string, status DeviceCodeStatus, userID *string) error

	// ConsumeDeviceCode atomically retrieves and removes/invalidates an approved device code record.
	// This operation MUST be single-use to protect against race conditions during concurrent polls.
	//
	// Function:
	//   Called when client polling detects approval and exchanges the device code for access tokens.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete single-use consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - deviceCode: Raw device code secret.
	//
	// Returns:
	//   - *DeviceCode: Consumed device code grant entity.
	//   - error: ErrAlreadyConsumed if already exchanged, ErrAuthorizationPending if not approved.
	//
	// Example SQL:
	//   DELETE FROM device_codes WHERE device_code = $1 AND status = 'approved' RETURNING id, device_code, user_code, status, user_id, expires_at, created_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "device:code:" + deviceCode).Bytes()
	ConsumeDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// DeleteDeviceCode removes a device code record from persistent storage.
	//
	// Function:
	//   Called during explicit cancellation or removal.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Device code eviction.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - deviceCode: Device code secret.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM device_codes WHERE device_code = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "device:code:" + deviceCode).Err()
	DeleteDeviceCode(ctx context.Context, deviceCode string) error

	// DeleteExpiredDeviceCodes purges all expired device code records.
	//
	// Function:
	//   Called by background cleanup crons.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM device_codes WHERE expires_at <= $1;
	DeleteExpiredDeviceCodes(ctx context.Context) error

	// GetUserByID retrieves a user entity by unique user identifier.
	//
	// Function:
	//   Used after successful device code exchange to create user session and populate identity.
	//
	// Storage:
	//   Database (GORM / SQL) - User primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrUserNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// SessionRepository provides session creation operations.
	repository.SessionRepository
}
