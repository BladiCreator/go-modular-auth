package organization

import (
	"context"
	"strings"
	"time"
)

// Dynamic Role Operations

// CreateRole creates a new dynamic organization-scoped custom role and its permission matrix.
func (p *Plugin) CreateRole(ctx context.Context, params CreateRoleParams) (*CreateRoleResult, error) {
	if !p.config.DynamicAccessControlEnabled {
		return nil, ErrDynamicACNotEnabled
	}
	if params.OrganizationID == "" || strings.TrimSpace(params.Role) == "" || params.Permissions == nil {
		return nil, ErrInvalidParameter
	}

	roleName := strings.TrimSpace(params.Role)

	// 1. RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, member.Role, Permissions{
			ResourceAccessControl: {ActionCreate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Check Role Limits
	if p.config.MaximumRolesPerOrganization != nil {
		maxRoles, err := p.config.MaximumRolesPerOrganization(ctx, params.OrganizationID)
		if err != nil {
			return nil, err
		}
		if maxRoles > 0 {
			count, err := p.repo.CountRoles(ctx, params.OrganizationID)
			if err != nil {
				return nil, err
			}
			if count >= maxRoles {
				return nil, ErrRolesLimitReached
			}
		}
	}

	// 3. Check for existing role with the same name
	existing, err := p.repo.GetRoleByName(ctx, params.OrganizationID, roleName)
	if err == nil && existing != nil {
		return nil, ErrRoleAlreadyExists
	}

	// 4. Emit Before Event
	p.publishEvent(EventRoleCreateBefore, &RoleCreateBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		Role:           roleName,
		Permissions:    params.Permissions,
		Extra:          params.Extra,
	})

	// 5. Create Role Entity
	orgRole := &OrganizationRole{
		ID:             generateRandomID("role_", 12),
		OrganizationID: params.OrganizationID,
		Role:           roleName,
		Permissions:    params.Permissions,
		CreatedAt:      time.Now(),
	}

	if err := p.repo.CreateRole(ctx, orgRole); err != nil {
		return nil, err
	}

	// 6. Emit After Event
	p.publishEvent(EventRoleCreateAfter, &RoleCreateAfterEventPayload{
		Role:  orgRole,
		Extra: params.Extra,
	})

	return &CreateRoleResult{Role: orgRole}, nil
}

// GetRole retrieves a dynamic role by its unique identifier.
func (p *Plugin) GetRole(ctx context.Context, params GetRoleParams) (*GetRoleResult, error) {
	if !p.config.DynamicAccessControlEnabled {
		return nil, ErrDynamicACNotEnabled
	}
	if params.RoleID == "" {
		return nil, ErrInvalidParameter
	}

	role, err := p.repo.GetRoleByID(ctx, params.RoleID)
	if err != nil {
		return nil, err
	}

	return &GetRoleResult{Role: role}, nil
}

// UpdateRole updates the name or permissions of an existing dynamic role.
func (p *Plugin) UpdateRole(ctx context.Context, params UpdateRoleParams) (*UpdateRoleResult, error) {
	if !p.config.DynamicAccessControlEnabled {
		return nil, ErrDynamicACNotEnabled
	}
	if params.RoleID == "" {
		return nil, ErrInvalidParameter
	}

	role, err := p.repo.GetRoleByID(ctx, params.RoleID)
	if err != nil {
		return nil, err
	}

	// RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, role.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, role.OrganizationID, member.Role, Permissions{
			ResourceAccessControl: {ActionUpdate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// Check name uniqueness if updated
	if params.Role != nil && *params.Role != "" && *params.Role != role.Role {
		newName := strings.TrimSpace(*params.Role)
		existing, err := p.repo.GetRoleByName(ctx, role.OrganizationID, newName)
		if err == nil && existing != nil && existing.ID != role.ID {
			return nil, ErrRoleAlreadyExists
		}
		role.Role = newName
	}

	if params.Permissions != nil {
		role.Permissions = params.Permissions
	}
	now := time.Now()
	role.UpdatedAt = &now

	p.publishEvent(EventRoleUpdateBefore, &RoleUpdateBeforeEventPayload{
		RoleID:      role.ID,
		Role:        params.Role,
		Permissions: params.Permissions,
		Extra:       params.Extra,
	})

	if err := p.repo.UpdateRole(ctx, role); err != nil {
		return nil, err
	}

	p.publishEvent(EventRoleUpdateAfter, &RoleUpdateAfterEventPayload{
		Role:  role,
		Extra: params.Extra,
	})

	return &UpdateRoleResult{Role: role}, nil
}

// DeleteRole deletes a dynamic role from an organization.
func (p *Plugin) DeleteRole(ctx context.Context, params DeleteRoleParams) (*DeleteRoleResult, error) {
	if !p.config.DynamicAccessControlEnabled {
		return nil, ErrDynamicACNotEnabled
	}
	if params.RoleID == "" {
		return nil, ErrInvalidParameter
	}

	role, err := p.repo.GetRoleByID(ctx, params.RoleID)
	if err != nil {
		return nil, err
	}

	// RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, role.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, role.OrganizationID, member.Role, Permissions{
			ResourceAccessControl: {ActionDelete},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	p.publishEvent(EventRoleDeleteBefore, &RoleDeleteBeforeEventPayload{
		RoleID: role.ID,
		Extra:  params.Extra,
	})

	if err := p.repo.DeleteRole(ctx, params.RoleID); err != nil {
		return nil, err
	}

	p.publishEvent(EventRoleDeleteAfter, &RoleDeleteAfterEventPayload{
		RoleID: role.ID,
		Extra:  params.Extra,
	})

	return &DeleteRoleResult{Success: true}, nil
}

// ListRoles retrieves all dynamic roles configured for an organization.
func (p *Plugin) ListRoles(ctx context.Context, params ListRolesParams) (*ListRolesResult, error) {
	if !p.config.DynamicAccessControlEnabled {
		return nil, ErrDynamicACNotEnabled
	}
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	roles, err := p.repo.ListRolesByOrgID(ctx, params.OrganizationID)
	if err != nil {
		return nil, err
	}

	return &ListRolesResult{Roles: roles}, nil
}

// HasPermission checks whether a specified user or role possesses the required permissions in an organization.
func (p *Plugin) HasPermission(ctx context.Context, params HasPermissionParams) (*HasPermissionResult, error) {
	if params.OrganizationID == "" || params.Permissions == nil {
		return nil, ErrInvalidParameter
	}

	role := params.Role
	if role == "" && params.UserID != "" {
		member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
		if err != nil {
			return &HasPermissionResult{HasPermission: false}, nil
		}
		role = member.Role
	}

	if role == "" {
		return &HasPermissionResult{HasPermission: false}, nil
	}

	allowed, err := p.CheckPermission(ctx, params.OrganizationID, role, params.Permissions)
	if err != nil {
		return nil, err
	}

	return &HasPermissionResult{HasPermission: allowed}, nil
}
