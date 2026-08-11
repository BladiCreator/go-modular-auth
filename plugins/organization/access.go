package organization

import (
	"context"
	"strings"
)

// Permissions maps resource identifiers to lists of granted actions (e.g. "member": ["create", "update"]).
type Permissions map[string][]string

// DefaultRoles defines the baseline permission matrix for built-in roles (owner, admin, member).
var DefaultRoles = map[string]Permissions{
	RoleOwner: {
		ResourceOrganization:  {ActionUpdate, ActionDelete},
		ResourceMember:        {ActionCreate, ActionUpdate, ActionDelete},
		ResourceInvitation:    {ActionCreate, ActionCancel},
		ResourceTeam:          {ActionCreate, ActionUpdate, ActionDelete},
		ResourceAccessControl: {ActionCreate, ActionRead, ActionUpdate, ActionDelete},
	},
	RoleAdmin: {
		ResourceOrganization:  {ActionUpdate},
		ResourceMember:        {ActionCreate, ActionUpdate, ActionDelete},
		ResourceInvitation:    {ActionCreate, ActionCancel},
		ResourceTeam:          {ActionCreate, ActionUpdate, ActionDelete},
		ResourceAccessControl: {ActionCreate, ActionRead, ActionUpdate, ActionDelete},
	},
	RoleMember: {
		ResourceAccessControl: {ActionRead},
	},
}

// ClonePermissions creates a deep copy of a Permissions map.
func ClonePermissions(p Permissions) Permissions {
	if p == nil {
		return make(Permissions)
	}
	clone := make(Permissions, len(p))
	for res, actions := range p {
		copiedActions := make([]string, len(actions))
		copy(copiedActions, actions)
		clone[res] = copiedActions
	}
	return clone
}

// MergePermissions combines source permissions into destination permissions without duplicates.
func MergePermissions(dst, src Permissions) Permissions {
	if dst == nil {
		dst = make(Permissions)
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

// EvaluatePermissions checks if a granted permissions matrix satisfies all required permissions.
func EvaluatePermissions(granted, required Permissions) bool {
	for reqResource, reqActions := range required {
		grantedActions, ok := granted[reqResource]
		if !ok {
			// Check for global resource wildcard
			if wildcardActions, hasWildcard := granted["*"]; hasWildcard {
				grantedActions = wildcardActions
			} else {
				return false
			}
		}

		for _, reqAction := range reqActions {
			if !HasAction(grantedActions, reqAction) {
				return false
			}
		}
	}
	return true
}

// ResolveRolePermissions collects all permissions granted to a given role string, resolving built-in roles,
// custom static roles, and dynamic organization roles when enabled. Supports compound roles (e.g. "admin,billing").
func (p *Plugin) ResolveRolePermissions(ctx context.Context, orgID, roleStr string) (Permissions, error) {
	merged := make(Permissions)
	roles := strings.Split(roleStr, ",")

	for _, rawRole := range roles {
		roleName := strings.TrimSpace(rawRole)
		if roleName == "" {
			continue
		}

		// 1. Check custom static roles configured on the plugin
		if p.config.CustomRoles != nil {
			if customPerms, ok := p.config.CustomRoles[roleName]; ok {
				MergePermissions(merged, customPerms)
			}
		}

		// 2. Check built-in default roles
		if defPerms, ok := DefaultRoles[roleName]; ok {
			MergePermissions(merged, defPerms)
		}

		// 3. If dynamic access control is enabled and repo is available, check dynamic roles in DB
		if p.config.DynamicAccessControlEnabled && p.repo != nil && orgID != "" {
			dbRole, err := p.repo.GetRoleByName(ctx, orgID, roleName)
			if err == nil && dbRole != nil && dbRole.Permissions != nil {
				MergePermissions(merged, dbRole.Permissions)
			}
		}
	}

	return merged, nil
}

// CheckPermission evaluates whether a user role possesses all required permissions in an organization.
func (p *Plugin) CheckPermission(ctx context.Context, orgID, userRole string, required Permissions) (bool, error) {
	if userRole == "" {
		return false, nil
	}

	granted, err := p.ResolveRolePermissions(ctx, orgID, userRole)
	if err != nil {
		return false, err
	}

	return EvaluatePermissions(granted, required), nil
}
