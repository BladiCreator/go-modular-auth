package organization

import (
	"context"
)

// RoleRepository defines the persistence operations for dynamic custom roles and permissions.
type RoleRepository interface {
	// CreateRole creates a dynamic custom role within an organization.
	CreateRole(ctx context.Context, role *OrganizationRole) error

	// GetRoleByID retrieves a custom dynamic role by ID.
	GetRoleByID(ctx context.Context, id string) (*OrganizationRole, error)

	// GetRoleByName retrieves a dynamic role by name within an organization.
	GetRoleByName(ctx context.Context, orgID, roleName string) (*OrganizationRole, error)

	// UpdateRole updates dynamic role permissions.
	UpdateRole(ctx context.Context, role *OrganizationRole) error

	// DeleteRole removes a custom dynamic role.
	DeleteRole(ctx context.Context, id string) error

	// ListRolesByOrgID lists all custom dynamic roles defined in an organization.
	ListRolesByOrgID(ctx context.Context, orgID string) ([]*OrganizationRole, error)

	// CountRoles counts custom dynamic roles defined in an organization.
	CountRoles(ctx context.Context, orgID string) (int, error)
}
