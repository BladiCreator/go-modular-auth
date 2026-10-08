// Package store defines the persistence contracts and data structures for API keys.
package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

var (
	// ErrNotFound is returned when the requested API key is not found in the store.
	ErrNotFound = errors.New("apikeys store: key not found")

	// ErrConflict is returned when an API key constraint is violated (e.g. duplicate ID or hash).
	ErrConflict = errors.New("apikeys store: key conflict")
)

// APIKey represents the persistent record of an API key.
// Secret tokens are NEVER stored; only KeyHash (SHA-256) and Prefix are kept.
type APIKey struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Prefix         string            `json:"prefix"`
	KeyHash        string            `json:"key_hash"`
	UserID         string            `json:"user_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	ServiceID      string            `json:"service_id,omitempty"`
	Scopes         []string          `json:"scopes,omitempty"`
	Permissions    []string          `json:"permissions,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
	LastUsedAt     *time.Time        `json:"last_used_at,omitempty"`
	LastUsedIP     string            `json:"last_used_ip,omitempty"`
	LastUsedUA     string            `json:"last_used_ua,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// IsRevoked reports whether the key has been revoked.
func (k *APIKey) IsRevoked() bool {
	return k.RevokedAt != nil
}

// IsExpired reports whether the key has expired.
func (k *APIKey) IsExpired(now time.Time) bool {
	return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
}

// IsActive reports whether the key is active (neither revoked nor expired).
func (k *APIKey) IsActive(now time.Time) bool {
	return !k.IsRevoked() && !k.IsExpired(now)
}

// HasScope checks if the key contains the specified scope.
func (k *APIKey) HasScope(scope string) bool {
	return slices.Contains(k.Scopes, scope)
}

// HasAllScopes checks if the key contains all specified scopes.
func (k *APIKey) HasAllScopes(scopes ...string) bool {
	for _, s := range scopes {
		if !k.HasScope(s) {
			return false
		}
	}
	return true
}

// HasAnyScope checks if the key contains at least one of the specified scopes.
func (k *APIKey) HasAnyScope(scopes ...string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if k.HasScope(s) {
			return true
		}
	}
	return false
}

// HasPermission checks if the key contains the specified permission.
func (k *APIKey) HasPermission(permission string) bool {
	return slices.Contains(k.Permissions, permission)
}

// HasAllPermissions checks if the key contains all specified permissions.
func (k *APIKey) HasAllPermissions(permissions ...string) bool {
	for _, p := range permissions {
		if !k.HasPermission(p) {
			return false
		}
	}
	return true
}

// HasAnyPermission checks if the key contains at least one of the specified permissions.
func (k *APIKey) HasAnyPermission(permissions ...string) bool {
	if len(permissions) == 0 {
		return true
	}
	for _, p := range permissions {
		if k.HasPermission(p) {
			return true
		}
	}
	return false
}

// ListFilter specifies filter and pagination criteria for querying API keys.
type ListFilter struct {
	UserID         string
	OrganizationID string
	ServiceID      string
	IncludeRevoked bool
	Limit          int
	Offset         int
}

// Store defines the persistence contract for API keys.
type Store interface {
	// Create persists a new API key record.
	Create(ctx context.Context, key *APIKey) error

	// GetByID retrieves an API key by its unique ID.
	GetByID(ctx context.Context, id string) (*APIKey, error)

	// GetByHash retrieves an API key by its SHA-256 hash digest.
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)

	// Update updates mutable attributes of an existing key.
	Update(ctx context.Context, key *APIKey) error

	// Revoke marks the key with the given ID as revoked.
	Revoke(ctx context.Context, id string, revokedAt time.Time) error

	// TouchLastUsed updates the last used timestamp and network telemetry for the key.
	TouchLastUsed(ctx context.Context, id string, at time.Time, ip string, ua string) error

	// List retrieves matching keys according to filter criteria.
	List(ctx context.Context, filter ListFilter) ([]*APIKey, error)

	// Delete permanently deletes an API key record.
	Delete(ctx context.Context, id string) error

	// DeleteExpired removes keys that expired prior to the cutoff timestamp.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
