package rbac

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
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
