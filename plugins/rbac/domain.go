package rbac

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// Scope defines the operational boundary where a role or assignment applies.
type Scope string

const (
	// ScopeGlobal applies across the entire system without boundary restrictions.
	ScopeGlobal Scope = "global"

	// ScopeOrganization scopes authorization within a specific tenant or organization.
	ScopeOrganization Scope = "organization"

	// ScopeService scopes authorization within a specific microservice or API boundary.
	ScopeService Scope = "service"
)

// Valid returns true if the scope is recognized.
func (s Scope) Valid() bool {
	switch s {
	case ScopeGlobal, ScopeOrganization, ScopeService:
		return true
	default:
		return false
	}
}

// Role represents a defined set of permissions within a specific scope.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scope       Scope     `json:"scope"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleAssignment binds a Core Principal to a Role within a given scope.
type RoleAssignment struct {
	ID               string             `json:"id"`
	RoleID           string             `json:"role_id"`
	PrincipalSubject string             `json:"principal_subject"`
	PrincipalType    auth.PrincipalType `json:"principal_type"`
	Scope            Scope              `json:"scope"`
	ScopeID          string             `json:"scope_id,omitempty"` // organization ID or service ID; empty if ScopeGlobal
	CreatedAt        time.Time          `json:"created_at"`
}

// Resource identifies the target entity or boundary being accessed.
type Resource struct {
	Type           string `json:"type,omitempty"`
	ID             string `json:"id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
}

// NewResource creates a general resource descriptor.
func NewResource(resType, id string) Resource {
	return Resource{
		Type: resType,
		ID:   id,
	}
}

// NewOrganizationResource creates an organization-scoped resource descriptor.
func NewOrganizationResource(resType, id, orgID string) Resource {
	return Resource{
		Type:           resType,
		ID:             id,
		OrganizationID: orgID,
	}
}

// NewServiceResource creates a service-scoped resource descriptor.
func NewServiceResource(resType, id, serviceID string) Resource {
	return Resource{
		Type:      resType,
		ID:        id,
		ServiceID: serviceID,
	}
}

// EmptyResource returns an empty resource.
func EmptyResource() Resource {
	return Resource{}
}

// Decision represents the structured outcome of an authorization evaluation.
type Decision struct {
	Allowed          bool               `json:"allowed"`
	Reason           string             `json:"reason,omitempty"`
	MatchedRole      string             `json:"matched_role,omitempty"`
	Permission       string             `json:"permission"`
	PrincipalSubject string             `json:"principal_subject"`
	PrincipalType    auth.PrincipalType `json:"principal_type"`
	EvaluatedAt      time.Time          `json:"evaluated_at"`
}

const (
	ModelRBACRoles       = "rbac_roles"
	ModelRBACAssignments = "rbac_assignments"
)

// RegisterSchema registers the rbac_roles and rbac_assignments models in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	roleModel := schema.NewModel(ModelRBACRoles, ModelRBACRoles, "id")
	_ = roleModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = roleModel.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true, Unique: true})
	_ = roleModel.AddField(schema.Field{Name: "description", Type: schema.TypeString})
	_ = roleModel.AddField(schema.Field{Name: "scope", Type: schema.TypeString, Required: true})
	_ = roleModel.AddField(schema.Field{Name: "permissions", Type: schema.TypeJSON, Required: true})
	_ = roleModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = roleModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	roleModel.Indexes = []schema.Index{
		{Name: "idx_rbac_roles_name", Fields: []string{"name"}, Unique: true},
		{Name: "idx_rbac_roles_scope", Fields: []string{"scope"}},
	}
	if err := s.AddModel(roleModel); err != nil {
		return err
	}

	asgnModel := schema.NewModel(ModelRBACAssignments, ModelRBACAssignments, "id")
	_ = asgnModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = asgnModel.AddField(schema.Field{Name: "role_id", Type: schema.TypeString, Required: true})
	_ = asgnModel.AddField(schema.Field{Name: "principal_subject", Type: schema.TypeString, Required: true})
	_ = asgnModel.AddField(schema.Field{Name: "principal_type", Type: schema.TypeString, Required: true})
	_ = asgnModel.AddField(schema.Field{Name: "scope", Type: schema.TypeString, Required: true})
	_ = asgnModel.AddField(schema.Field{Name: "scope_id", Type: schema.TypeString})
	_ = asgnModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	asgnModel.Indexes = []schema.Index{
		{Name: "idx_rbac_assignments_principal", Fields: []string{"principal_subject", "principal_type"}},
		{Name: "idx_rbac_assignments_role", Fields: []string{"role_id"}},
		{Name: "idx_rbac_assignments_scope", Fields: []string{"scope", "scope_id"}},
	}
	return s.AddModel(asgnModel)
}
