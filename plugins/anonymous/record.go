package anonymous

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// Identity represents the persistent record of an anonymous identity in the system.
type Identity struct {
	ID           string            `json:"id"`
	UserID       string            `json:"user_id"`
	ExpiresAt    time.Time         `json:"expires_at"`
	ConvertedAt  *time.Time        `json:"converted_at,omitempty"`
	LinkedUserID string            `json:"linked_user_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Expired reports whether the anonymous identity is expired at the given instant.
func (i *Identity) Expired(now time.Time) bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(i.ExpiresAt)
}

// Converted reports whether the identity has been converted to permanent or linked.
func (i *Identity) Converted() bool {
	return i.ConvertedAt != nil
}

// IsActive reports whether the identity is currently valid, unexpired, and unconverted.
func (i *Identity) IsActive(now time.Time) bool {
	return !i.Converted() && !i.Expired(now)
}

const (
	ModelAnonymousIdentities = "anonymous_identities"
)

// RegisterSchema registers the anonymous_identities model with the unified schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelAnonymousIdentities, ModelAnonymousIdentities, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "converted_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "linked_user_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_anon_user_id", Fields: []string{"user_id"}, Unique: true},
		{Name: "idx_anon_expires_at", Fields: []string{"expires_at"}},
	}

	return s.AddModel(m)
}
