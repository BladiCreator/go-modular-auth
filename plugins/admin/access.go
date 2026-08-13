package admin

import (
	"strings"
	"sync"
)

// Statements defines the actions permitted per resource for a role.
// Example: map[string][]string{"user": {"create", "list", "ban"}, "session": {"list", "revoke"}}
type Statements map[string][]string

// Permissions represents the set of permissions required to perform an administrative operation.
type Permissions map[string][]string

// Connector defines the logical evaluation operator for combining permission checks.
type Connector string

const (
	// ConnectorAND requires that all specified resource actions must be satisfied.
	ConnectorAND Connector = "AND"
	// ConnectorOR requires that at least one specified resource action must be satisfied.
	ConnectorOR Connector = "OR"
)

// AuthorizeResult represents the outcome of a role permission evaluation.
type AuthorizeResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Role represents a named role definition paired with its granted statements.
type Role struct {
	Name       string     `json:"name"`
	Statements Statements `json:"statements"`
}

// DefaultRoles defines the baseline permission matrix for built-in roles (admin, user).
func DefaultRoles() map[string]Role {
	return map[string]Role{
		RoleAdmin: {
			Name: RoleAdmin,
			Statements: Statements{
				ResourceUser: {
					ActionCreate,
					ActionList,
					ActionGet,
					ActionUpdate,
					ActionDelete,
					ActionSetRole,
					ActionBan,
					ActionImpersonate,
					ActionSetPassword,
					ActionSetEmail,
				},
				ResourceSession: {
					ActionSessionList,
					ActionSessionRevoke,
					ActionSessionDelete,
				},
			},
		},
		RoleUser: {
			Name:       RoleUser,
			Statements: Statements{},
		},
	}
}

// CloneStatements creates a deep copy of a Statements map.
func CloneStatements(s Statements) Statements {
	if s == nil {
		return make(Statements)
	}
	clone := make(Statements, len(s))
	for res, actions := range s {
		copiedActions := make([]string, len(actions))
		copy(copiedActions, actions)
		clone[res] = copiedActions
	}
	return clone
}

// MergeStatements combines source statements into destination statements without duplicates.
func MergeStatements(dst, src Statements) Statements {
	if dst == nil {
		dst = make(Statements)
	}
	for res, actions := range src {
		existing := dst[res]
		for _, act := range actions {
			if !HasAction(existing, act) {
				existing = append(existing, act)
			}
		}
		dst[res] = existing
	}
	return dst
}

// HasAction checks if a target action is present in an action list (or matches wildcard "*").
func HasAction(actions []string, targetAction string) bool {
	for _, act := range actions {
		if act == "*" || strings.EqualFold(act, targetAction) {
			return true
		}
	}
	return false
}

// CheckActionGranted checks if a specific action on a resource is satisfied by the granted statements (with wildcard support).
func CheckActionGranted(granted Statements, resource, action string) bool {
	if actions, ok := granted[resource]; ok {
		if HasAction(actions, action) {
			return true
		}
	}
	if actions, ok := granted["*"]; ok {
		if HasAction(actions, action) {
			return true
		}
	}
	return false
}

// EvaluateStatements evaluates whether granted statements satisfy the requested permissions using the given connector.
func EvaluateStatements(granted Statements, requested Permissions, connector Connector) bool {
	if len(requested) == 0 {
		return true
	}

	if connector == ConnectorOR {
		for reqResource, reqActions := range requested {
			if len(reqActions) == 0 {
				if _, ok := granted[reqResource]; ok {
					return true
				}
				if _, ok := granted["*"]; ok {
					return true
				}
			}
			for _, reqAction := range reqActions {
				if CheckActionGranted(granted, reqResource, reqAction) {
					return true
				}
			}
		}
		return false
	}

	// Default: ConnectorAND
	for reqResource, reqActions := range requested {
		for _, reqAction := range reqActions {
			if !CheckActionGranted(granted, reqResource, reqAction) {
				return false
			}
		}
	}
	return true
}

// Authorize evaluates whether the role satisfies the requested permissions.
func (r *Role) Authorize(requested Permissions, connector Connector) AuthorizeResult {
	if r == nil {
		return AuthorizeResult{Success: false, Error: "nil role"}
	}
	if EvaluateStatements(r.Statements, requested, connector) {
		return AuthorizeResult{Success: true}
	}
	return AuthorizeResult{Success: false, Error: "forbidden: insufficient permissions"}
}

// AccessControl manages the registry of roles configured within the application.
type AccessControl struct {
	mu    sync.RWMutex
	roles map[string]Role
}

// NewAccessControl initializes a new AccessControl instance populated with default roles.
func NewAccessControl() *AccessControl {
	ac := &AccessControl{
		roles: make(map[string]Role),
	}
	for name, role := range DefaultRoles() {
		ac.roles[name] = role
	}
	return ac
}

// RegisterRole adds or overrides a role definition in the access control registry.
func (ac *AccessControl) RegisterRole(role Role) *AccessControl {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.roles[role.Name] = role
	return ac
}

// GetRole retrieves a role by name from the registry.
func (ac *AccessControl) GetRole(name string) (Role, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	role, ok := ac.roles[name]
	return role, ok
}

// Roles returns a copy of all registered roles in the registry.
func (ac *AccessControl) Roles() map[string]Role {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	copyMap := make(map[string]Role, len(ac.roles))
	for k, v := range ac.roles {
		copyMap[k] = Role{
			Name:       v.Name,
			Statements: CloneStatements(v.Statements),
		}
	}
	return copyMap
}

// HasPermissionInput defines the parameters passed to HasPermission.
type HasPermissionInput struct {
	UserID       string
	Role         string
	AdminUserIDs []string
	RolesConfig  map[string]Role
	DefaultRole  string
	Permissions  Permissions
	Connector    Connector
}

// HasPermission verifies whether a caller possesses the required permissions considering their roles, custom configs, and AdminUserIDs bypass.
func HasPermission(input HasPermissionInput) bool {
	if input.UserID != "" && len(input.AdminUserIDs) > 0 {
		for _, adminID := range input.AdminUserIDs {
			if input.UserID == adminID {
				return true
			}
		}
	}

	if len(input.Permissions) == 0 {
		return true
	}

	roleStr := strings.TrimSpace(input.Role)
	if roleStr == "" {
		roleStr = input.DefaultRole
	}
	if roleStr == "" {
		return false
	}

	merged := make(Statements)
	roleParts := strings.Split(roleStr, ",")

	for _, rawPart := range roleParts {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}

		if input.RolesConfig != nil {
			if customRole, ok := input.RolesConfig[part]; ok {
				MergeStatements(merged, customRole.Statements)
				continue
			}
		}

		if defRole, ok := DefaultRoles()[part]; ok {
			MergeStatements(merged, defRole.Statements)
		}
	}

	return EvaluateStatements(merged, input.Permissions, input.Connector)
}
