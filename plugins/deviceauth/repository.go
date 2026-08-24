package deviceauth

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
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
type Repository interface {
	// CreateDeviceCode persists a new device authorization grant record in storage.
	CreateDeviceCode(ctx context.Context, code *DeviceCode) error

	// FindByDeviceCode retrieves an active device code record by its device_code secret.
	FindByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// FindByUserCode retrieves an active device code record by its normalized user_code.
	FindByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// UpdateLastPolledAt updates the last_polled_at timestamp for rate limiting checks.
	UpdateLastPolledAt(ctx context.Context, deviceCode string, polledAt time.Time) error

	// UpdateStatus updates the status (approved/denied) and optional owner userID for a device code by userCode.
	UpdateStatus(ctx context.Context, userCode string, status DeviceCodeStatus, userID *string) error

	// ConsumeDeviceCode atomically retrieves and removes/invalidates an approved device code record.
	// This operation MUST be single-use to protect against race conditions during concurrent polls.
	ConsumeDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// DeleteDeviceCode removes a device code record from persistent storage.
	DeleteDeviceCode(ctx context.Context, deviceCode string) error

	// DeleteExpiredDeviceCodes purges all expired device code records.
	DeleteExpiredDeviceCodes(ctx context.Context) error

	// GetUserByID retrieves a user entity by unique user identifier.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// CreateSession initializes and persists an active user session entity.
	CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error)
}
