// Package apikeys provides API key authentication, lifecycle management, and resolution
// into GoModularAuth Core Principal semantics.
package apikeys

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-apikeys/store"
)

// APIKey represents the persistent, non-secret state of an issued API key.
type APIKey = store.APIKey

// ListFilter specifies criteria for querying API keys.
type ListFilter = store.ListFilter

// Store is the persistence interface required by the API keys plugin.
type Store = store.Store

type apiKeyContextKey struct{}

// WithAPIKey stores an authenticated APIKey in the context. Transport middleware
// should attach this after a successful Authenticate call.
func WithAPIKey(ctx context.Context, key *APIKey) context.Context {
	return context.WithValue(ctx, apiKeyContextKey{}, key)
}

// APIKeyFrom retrieves the APIKey stored in ctx, if present.
func APIKeyFrom(ctx context.Context) (*APIKey, bool) {
	key, ok := ctx.Value(apiKeyContextKey{}).(*APIKey)
	return key, ok
}

// CreateInput contains parameters required to create an API key.
type CreateInput struct {
	Name           string
	UserID         string
	OrganizationID string
	ServiceID      string
	Scopes         []string
	Permissions    []string
	Metadata       map[string]string
	ExpiresAt      *time.Time
	ExpiresIn      time.Duration
	Prefix         string
}

// CreateResult returns the newly persisted API key record along with the
// single-use plaintext key secret.
type CreateResult struct {
	Key    *APIKey
	RawKey string
}

// RotateOption configures an API key rotation.
type RotateOption func(*rotateConfig)

type rotateConfig struct {
	gracePeriod    time.Duration
	newName        *string
	newScopes      []string
	newPermissions []string
	newMetadata    map[string]string
	newExpiresIn   *time.Duration
}

// WithGracePeriod specifies how long the old API key remains valid before expiring.
// If zero or not provided, the old key is immediately revoked.
func WithGracePeriod(d time.Duration) RotateOption {
	return func(c *rotateConfig) {
		c.gracePeriod = d
	}
}

// WithNewName overrides the name of the newly generated key during rotation.
func WithNewName(name string) RotateOption {
	return func(c *rotateConfig) {
		c.newName = &name
	}
}

// WithNewScopes overrides the scopes granted to the rotated key.
func WithNewScopes(scopes []string) RotateOption {
	return func(c *rotateConfig) {
		c.newScopes = scopes
	}
}

// WithNewPermissions overrides the permissions granted to the rotated key.
func WithNewPermissions(perms []string) RotateOption {
	return func(c *rotateConfig) {
		c.newPermissions = perms
	}
}

// WithNewMetadata overrides the custom metadata on the rotated key.
func WithNewMetadata(meta map[string]string) RotateOption {
	return func(c *rotateConfig) {
		c.newMetadata = meta
	}
}

// WithNewExpiresIn sets a new relative expiration duration on the rotated key.
func WithNewExpiresIn(d time.Duration) RotateOption {
	return func(c *rotateConfig) {
		c.newExpiresIn = &d
	}
}

// RotateResult contains the newly issued key, its plaintext secret, and the updated old key.
type RotateResult struct {
	NewKey *APIKey
	RawKey string
	OldKey *APIKey
}

// AuthOption configures authentication validation and telemetry.
type AuthOption func(*authConfig)

type authConfig struct {
	ipAddress           string
	userAgent           string
	requiredScopes      []string
	requiredPermissions []string
}

// WithIPAddress records the client IP address on the API key's last used telemetry.
func WithIPAddress(ip string) AuthOption {
	return func(c *authConfig) {
		c.ipAddress = ip
	}
}

// WithUserAgent records the client User-Agent header on the API key's last used telemetry.
func WithUserAgent(ua string) AuthOption {
	return func(c *authConfig) {
		c.userAgent = ua
	}
}

// WithRequiredScopes enforces that the authenticated key must possess all given scopes.
func WithRequiredScopes(scopes ...string) AuthOption {
	return func(c *authConfig) {
		c.requiredScopes = append(c.requiredScopes, scopes...)
	}
}

// WithRequiredPermissions enforces that the authenticated key must possess all given permissions.
func WithRequiredPermissions(perms ...string) AuthOption {
	return func(c *authConfig) {
		c.requiredPermissions = append(c.requiredPermissions, perms...)
	}
}

// AuthResult is returned when an API key is successfully authenticated.
// In accordance with GoModularAuth architecture, API key authentication resolves
// directly to an auth.Principal and does NOT create or return an HTTP User Session.
type AuthResult struct {
	Principal auth.Principal
	Key       *APIKey
}

// APIKeys defines the strongly typed capability interface for API key authentication.
type APIKeys interface {
	// Create generates and stores a new API key, returning the plaintext key once.
	Create(ctx context.Context, in CreateInput) (*CreateResult, error)

	// Get retrieves an API key by its unique ID.
	Get(ctx context.Context, id string) (*APIKey, error)

	// List queries API keys based on ownership filters.
	List(ctx context.Context, filter ListFilter) ([]*APIKey, error)

	// Revoke immediately revokes an API key and purges it from any cache.
	Revoke(ctx context.Context, id string) error

	// Rotate replaces an existing key with a newly generated key, optionally preserving
	// the old key during a grace period.
	Rotate(ctx context.Context, id string, opts ...RotateOption) (*RotateResult, error)

	// Authenticate validates a raw API key, checks expiration and scopes,
	// updates last-used telemetry, and resolves to an auth.Principal.
	Authenticate(ctx context.Context, rawKey string, opts ...AuthOption) (*AuthResult, error)

	// Delete permanently deletes an API key record and invalidates cache entries.
	Delete(ctx context.Context, id string) error

	// PurgeExpired deletes expired and revoked keys from persistence.
	PurgeExpired(ctx context.Context) (int, error)

	// Hooks provides access to the API key workflow lifecycle hooks.
	Hooks() *Hooks
}
