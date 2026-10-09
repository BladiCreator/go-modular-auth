package store

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Scope defines the operational boundary where a role applies.
type Scope string

const (
	ScopeGlobal       Scope = "global"
	ScopeOrganization Scope = "organization"
	ScopeService      Scope = "service"
)

// Role persistence model.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scope       Scope     `json:"scope"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleAssignment persistence model.
type RoleAssignment struct {
	ID               string             `json:"id"`
	RoleID           string             `json:"role_id"`
	PrincipalSubject string             `json:"principal_subject"`
	PrincipalType    auth.PrincipalType `json:"principal_type"`
	Scope            Scope              `json:"scope"`
	ScopeID          string             `json:"scope_id,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
}

// Store defines the persistence contract required by the RBAC plugin.
type Store interface {
	CreateRole(ctx context.Context, role *Role) error
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id string) error
	ListRoles(ctx context.Context, scope Scope) ([]*Role, error)

	CreateAssignment(ctx context.Context, assignment *RoleAssignment) error
	DeleteAssignment(ctx context.Context, id string) error
	GetAssignment(ctx context.Context, id string) (*RoleAssignment, error)
	ListAssignmentsByPrincipal(ctx context.Context, subject string, pType auth.PrincipalType) ([]*RoleAssignment, error)
	ListAssignmentsByRole(ctx context.Context, roleID string) ([]*RoleAssignment, error)
	DeleteAssignmentsByRole(ctx context.Context, roleID string) error
	DeleteAssignmentsByPrincipal(ctx context.Context, subject string) error
}
