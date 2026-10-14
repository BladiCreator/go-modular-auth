package username

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// Record is the persistent representation of a username mapping.
type Record struct {
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`   // Display username in original casing
	Normalized string    `json:"normalized"` // Canonical search key for uniqueness & lookups
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

const (
	ModelUsernames = "usernames"
)

// RegisterSchema registers the usernames model with the unified schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelUsernames, ModelUsernames, "user_id")
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "username", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "normalized", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_usernames_normalized", Fields: []string{"normalized"}, Unique: true},
	}

	return s.AddModel(m)
}
