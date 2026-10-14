package scim

import (
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

var (
	ErrNotFound       = errors.New("scim: resource not found")
	ErrConflict       = errors.New("scim: resource conflict")
	ErrInvalidRequest = errors.New("scim: invalid request")
	ErrSchemaMismatch = errors.New("scim: schema mismatch")
)

const (
	ModelSCIMUserMetadata = "scim_user_metadata"
	ModelSCIMGroups       = "scim_groups"
)

// UserMetadata stores SCIM-specific attributes bound to a Core User.
type UserMetadata struct {
	UserID     string    `json:"user_id"`
	ExternalID string    `json:"external_id"`
	Active     bool      `json:"active"`
	GivenName  string    `json:"given_name"`
	FamilyName string    `json:"family_name"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// GroupRecord represents a provisioned SCIM group.
type GroupRecord struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	MemberIDs   []string  `json:"member_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RegisterSchema registers SCIM user metadata and group models in the unified schema.
func RegisterSchema(s *schema.Schema) error {
	um := schema.NewModel(ModelSCIMUserMetadata, ModelSCIMUserMetadata, "user_id")
	_ = um.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = um.AddField(schema.Field{Name: "external_id", Type: schema.TypeString})
	_ = um.AddField(schema.Field{Name: "active", Type: schema.TypeBool, Required: true})
	_ = um.AddField(schema.Field{Name: "given_name", Type: schema.TypeString})
	_ = um.AddField(schema.Field{Name: "family_name", Type: schema.TypeString})
	_ = um.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = um.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	um.Indexes = []schema.Index{
		{Name: "idx_scim_user_metadata_ext", Fields: []string{"external_id"}},
	}
	if err := s.AddModel(um); err != nil {
		return err
	}

	gm := schema.NewModel(ModelSCIMGroups, ModelSCIMGroups, "id")
	_ = gm.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = gm.AddField(schema.Field{Name: "display_name", Type: schema.TypeString, Required: true})
	_ = gm.AddField(schema.Field{Name: "member_ids", Type: schema.TypeJSON})
	_ = gm.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = gm.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	return s.AddModel(gm)
}
