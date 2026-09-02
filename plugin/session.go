package plugin

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// SessionManager defines the contract for central session management exposed to plugins and the core engine.
type SessionManager interface {
	// CreateSession creates and persists a new authenticated user session.
	CreateSession(ctx context.Context, userID string, opts ...SessionOption) (*entity.Session, error)
	// ValidateSession validates a session token, returning combined user and session data.
	ValidateSession(ctx context.Context, token string) (*dto.SessionData, error)
	// RevokeSession revokes an active session by its unique raw token string.
	RevokeSession(ctx context.Context, token string) error
	// GetSessionByToken retrieves an active session by its token string without loading the user.
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)
}

// SessionOptions holds configurable options when creating or modifying a session.
type SessionOptions struct {
	// Duration overrides the default validity duration for the session.
	Duration time.Duration
	// RememberMe indicates whether to apply the extended remember-me session duration.
	RememberMe bool
	// IPAddress records the client IP address initiating the session.
	IPAddress string
	// UserAgent records the client user agent string initiating the session.
	UserAgent string
	// DeviceID optionally identifies the physical device initiating the session.
	DeviceID string
	// ExtraContainer provides dynamic key-value metadata for the session.
	ExtraContainer
}

// SessionOption represents a functional option for configuring session creation.
type SessionOption func(*SessionOptions)

// WithDuration sets a custom expiration duration for the session.
func WithDuration(d time.Duration) SessionOption {
	return func(o *SessionOptions) {
		o.Duration = d
	}
}

// WithRememberMe toggles extended session lifetime.
func WithRememberMe(remember bool) SessionOption {
	return func(o *SessionOptions) {
		o.RememberMe = remember
	}
}

// WithIPAddress sets the client IP address for the session.
func WithIPAddress(ip string) SessionOption {
	return func(o *SessionOptions) {
		o.IPAddress = ip
	}
}

// WithUserAgent sets the client User-Agent string for the session.
func WithUserAgent(ua string) SessionOption {
	return func(o *SessionOptions) {
		o.UserAgent = ua
	}
}

// WithDeviceID sets the device identifier for the session.
func WithDeviceID(deviceID string) SessionOption {
	return func(o *SessionOptions) {
		o.DeviceID = deviceID
	}
}

// WithExtra sets a dynamic key-value pair in the session extra metadata.
func WithExtra(key string, val any) SessionOption {
	return func(o *SessionOptions) {
		o.Set(key, val)
	}
}

// WithExtraMap copies a map of key-value pairs into the session extra metadata.
func WithExtraMap(m map[string]any) SessionOption {
	return func(o *SessionOptions) {
		for k, v := range m {
			o.Set(k, v)
		}
	}
}
