package apikeys

import (
	"slices"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
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

const (
	ModelAPIKeys = "api_keys"
)

// RegisterSchema registers the api_keys model into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelAPIKeys, ModelAPIKeys, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "prefix", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "key_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "service_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "permissions", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "last_used_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "last_used_ip", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "last_used_ua", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_api_keys_hash", Fields: []string{"key_hash"}, Unique: true},
		{Name: "idx_api_keys_user", Fields: []string{"user_id"}},
		{Name: "idx_api_keys_org", Fields: []string{"organization_id"}},
		{Name: "idx_api_keys_service", Fields: []string{"service_id"}},
	}

	return s.AddModel(m)
}
