package rbac

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
)

// RBAC is the strongly typed capability exposed by the gomodularauth-rbac plugin.
type RBAC interface {
	// Authorize evaluates whether principal is granted permission on the target resource.
	// Returns nil if authorized, or ErrForbidden if unauthorized.
	Authorize(ctx context.Context, principal auth.Principal, permission string, resource Resource) error

	// IsAuthorized performs deterministic evaluation and returns true if authorized, false if not.
	IsAuthorized(ctx context.Context, principal auth.Principal, permission string, resource Resource) (bool, error)

	// Evaluate provides detailed evaluation metadata including matched role and reason.
	Evaluate(ctx context.Context, principal auth.Principal, permission string, resource Resource) (*Decision, error)

	// CreateRole registers a new role definition.
	CreateRole(ctx context.Context, role *Role) error

	// GetRole retrieves a role by its unique ID.
	GetRole(ctx context.Context, roleID string) (*Role, error)

	// GetRoleByName retrieves a role by its unique name.
	GetRoleByName(ctx context.Context, name string) (*Role, error)

	// UpdateRole updates an existing role definition and invalidates related caches.
	UpdateRole(ctx context.Context, role *Role) error

	// DeleteRole removes an existing role, failing if active assignments exist.
	DeleteRole(ctx context.Context, roleID string) error

	// ListRoles lists roles filtered by scope, or all roles if scope is empty.
	ListRoles(ctx context.Context, scope Scope) ([]*Role, error)

	// AssignRole grants a role to a principal within the specified scope.
	AssignRole(ctx context.Context, assignment *RoleAssignment) error

	// RevokeRole removes a specific role assignment.
	RevokeRole(ctx context.Context, assignmentID string) error

	// ListAssignmentsByPrincipal returns all active role assignments for a principal.
	ListAssignmentsByPrincipal(ctx context.Context, principal auth.Principal) ([]*RoleAssignment, error)

	// ListAssignmentsByRole returns all active assignments associated with a role ID.
	ListAssignmentsByRole(ctx context.Context, roleID string) ([]*RoleAssignment, error)

	// InvalidatePrincipalCache evicts all cached authorization decisions for a principal.
	InvalidatePrincipalCache(ctx context.Context, principalSubject string) error

	// InvalidateAllCache purges all authorization evaluation caches.
	InvalidateAllCache(ctx context.Context) error
}
