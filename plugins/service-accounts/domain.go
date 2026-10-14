package serviceaccounts

import (
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

var (
	ErrNotFound       = errors.New("serviceaccounts: not found")
	ErrInactive       = errors.New("serviceaccounts: account is inactive")
	ErrInvalidSecret  = errors.New("serviceaccounts: invalid credentials")
	ErrInvalidName    = errors.New("serviceaccounts: name is required")
	ErrInvalidOwnerID = errors.New("serviceaccounts: owner_id is required")
)

const (
	ModelServiceAccounts = "service_accounts"
)

// ServiceAccount represents a machine-to-machine (M2M) identity.
type ServiceAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	OwnerID     string    `json:"owner_id"`
	Scopes      []string  `json:"scopes"`
	SecretHash  string    `json:"secret_hash"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	OwnerID     string   `json:"owner_id"`
	Scopes      []string `json:"scopes,omitempty"`
}

// RegisterSchema registers the service_accounts model in the schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelServiceAccounts, ModelServiceAccounts, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "description", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "owner_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "secret_hash", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "active", Type: schema.TypeBool, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	m.Indexes = []schema.Index{
		{Name: "idx_service_accounts_owner_id", Fields: []string{"owner_id"}},
	}
	return s.AddModel(m)
}
