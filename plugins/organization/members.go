package organization

import (
	"context"
	"strings"
	"time"
)

// Member Operations

// AddMember adds a user as a member to an organization with a specified role after checking membership limits and RBAC permissions.
func (p *Plugin) AddMember(ctx context.Context, params AddMemberParams) (*AddMemberResult, error) {
	if params.OrganizationID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	role := params.Role
	if strings.TrimSpace(role) == "" {
		role = RoleMember
	}

	// 1. RBAC Permission Check if InvokingUserID is provided
	if params.InvokingUserID != "" {
		invoker, err := p.repo.GetMember(ctx, params.OrganizationID, params.InvokingUserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, invoker.Role, Permissions{
			ResourceMember: {ActionCreate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Check if user is already a member
	existing, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
	if err == nil && existing != nil {
		return nil, ErrMemberAlreadyExists
	}

	// 3. Check Membership Limit
	if p.config.MembershipLimit != nil {
		maxMembers, err := p.config.MembershipLimit(ctx, params.OrganizationID)
		if err != nil {
			return nil, err
		}
		if maxMembers > 0 {
			count, err := p.repo.CountMembers(ctx, params.OrganizationID)
			if err != nil {
				return nil, err
			}
			if count >= maxMembers {
				return nil, ErrMembershipLimitReached
			}
		}
	}

	// 4. Emit Before Event
	p.publishEvent(EventMemberAddBefore, &MemberAddBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		Role:           role,
		Extra:          params.Extra,
	})

	// 5. Create Member Entity
	member := &Member{
		ID:             generateRandomID("mem_", 12),
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		Role:           role,
		CreatedAt:      time.Now(),
	}

	if err := p.repo.CreateMember(ctx, member); err != nil {
		return nil, err
	}

	// 6. Emit After Event
	p.publishEvent(EventMemberAddAfter, &MemberAddAfterEventPayload{
		Member: member,
		Extra:  params.Extra,
	})

	return &AddMemberResult{Member: member}, nil
}

// GetMember retrieves a membership record by organization ID and user ID.
func (p *Plugin) GetMember(ctx context.Context, params GetMemberParams) (*GetMemberResult, error) {
	if params.OrganizationID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
	if err != nil {
		return nil, err
	}

	return &GetMemberResult{Member: member}, nil
}

// GetActiveMember retrieves the membership record for a user in their active (or specified) organization.
func (p *Plugin) GetActiveMember(ctx context.Context, params GetActiveMemberParams) (*GetActiveMemberResult, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	orgID := params.OrganizationID
	if orgID == "" {
		if p.ctx != nil {
			if val, ok := p.ctx.Get(ActiveOrgContextKey(params.UserID)); ok {
				if idStr, ok := val.(string); ok {
					orgID = idStr
				}
			}
		}
	}

	if orgID == "" {
		userOrgs, err := p.repo.ListOrganizationsByUserID(ctx, params.UserID)
		if err != nil || len(userOrgs) == 0 {
			return nil, ErrOrganizationNotFound
		}
		orgID = userOrgs[0].ID
	}

	member, err := p.repo.GetMember(ctx, orgID, params.UserID)
	if err != nil {
		return nil, err
	}

	return &GetActiveMemberResult{Member: member}, nil
}

// GetActiveMemberRole retrieves the assigned role name of a user in their active (or specified) organization.
func (p *Plugin) GetActiveMemberRole(ctx context.Context, params GetActiveMemberRoleParams) (*GetActiveMemberRoleResult, error) {
	res, err := p.GetActiveMember(ctx, GetActiveMemberParams{
		UserID:         params.UserID,
		OrganizationID: params.OrganizationID,
		Extra:          params.Extra,
	})
	if err != nil {
		return nil, err
	}

	return &GetActiveMemberRoleResult{Role: res.Member.Role}, nil
}

// UpdateMemberRole updates the role assigned to a member, enforcing last-owner safety protection.
func (p *Plugin) UpdateMemberRole(ctx context.Context, params UpdateMemberRoleParams) (*UpdateMemberRoleResult, error) {
	if params.OrganizationID == "" || params.UserID == "" || strings.TrimSpace(params.Role) == "" {
		return nil, ErrInvalidParameter
	}

	// 1. RBAC Permission Check if InvokingUserID is provided
	if params.InvokingUserID != "" {
		invoker, err := p.repo.GetMember(ctx, params.OrganizationID, params.InvokingUserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, invoker.Role, Permissions{
			ResourceMember: {ActionUpdate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Fetch existing member
	member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
	if err != nil {
		return nil, err
	}

	// 3. Protect last owner demotion
	if strings.Contains(member.Role, RoleOwner) && !strings.Contains(params.Role, RoleOwner) {
		ownerCount, err := p.repo.CountMembersByRole(ctx, params.OrganizationID, RoleOwner)
		if err != nil {
			return nil, err
		}
		if ownerCount <= 1 {
			return nil, ErrCannotRemoveLastOwner
		}
	}

	// 4. Emit Before Event
	p.publishEvent(EventMemberRoleUpdateBefore, &MemberRoleUpdateBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		NewRole:        params.Role,
		Extra:          params.Extra,
	})

	// 5. Persist Role Update
	member.Role = strings.TrimSpace(params.Role)
	now := time.Now()
	member.UpdatedAt = &now

	if err := p.repo.UpdateMember(ctx, member); err != nil {
		return nil, err
	}

	// 6. Emit After Event
	p.publishEvent(EventMemberRoleUpdateAfter, &MemberRoleUpdateAfterEventPayload{
		Member: member,
		Extra:  params.Extra,
	})

	return &UpdateMemberRoleResult{Member: member}, nil
}

// RemoveMember deletes a user's membership from an organization, enforcing last-owner safety protection.
func (p *Plugin) RemoveMember(ctx context.Context, params RemoveMemberParams) (*RemoveMemberResult, error) {
	if params.OrganizationID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	// 1. RBAC Permission Check if InvokingUserID is provided
	if params.InvokingUserID != "" {
		invoker, err := p.repo.GetMember(ctx, params.OrganizationID, params.InvokingUserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, invoker.Role, Permissions{
			ResourceMember: {ActionDelete},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Fetch existing member
	member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
	if err != nil {
		return nil, err
	}

	// 3. Protect last owner removal
	if strings.Contains(member.Role, RoleOwner) {
		ownerCount, err := p.repo.CountMembersByRole(ctx, params.OrganizationID, RoleOwner)
		if err != nil {
			return nil, err
		}
		if ownerCount <= 1 {
			return nil, ErrCannotRemoveLastOwner
		}
	}

	// 4. Emit Before Event
	p.publishEvent(EventMemberRemoveBefore, &MemberRemoveBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		Extra:          params.Extra,
	})

	// 5. Persist Member Removal
	if err := p.repo.DeleteMember(ctx, params.OrganizationID, params.UserID); err != nil {
		return nil, err
	}

	// 6. Emit After Event
	p.publishEvent(EventMemberRemoveAfter, &MemberRemoveAfterEventPayload{
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		Extra:          params.Extra,
	})

	return &RemoveMemberResult{Success: true}, nil
}

// LeaveOrganization allows a user to voluntarily leave an organization, preventing the last owner from leaving without transferring ownership.
func (p *Plugin) LeaveOrganization(ctx context.Context, params LeaveOrganizationParams) (*LeaveOrganizationResult, error) {
	if params.OrganizationID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	// 1. Fetch existing member
	member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
	if err != nil {
		return nil, err
	}

	// 2. Protect last owner departure
	if strings.Contains(member.Role, RoleOwner) {
		ownerCount, err := p.repo.CountMembersByRole(ctx, params.OrganizationID, RoleOwner)
		if err != nil {
			return nil, err
		}
		if ownerCount <= 1 {
			return nil, ErrCannotLeaveAsLastOwner
		}
	}

	// 3. Emit Before Event
	p.publishEvent(EventMemberLeaveBefore, &MemberLeaveBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		Extra:          params.Extra,
	})

	// 4. Persist Deletion
	if err := p.repo.DeleteMember(ctx, params.OrganizationID, params.UserID); err != nil {
		return nil, err
	}

	// 5. Emit After Event
	p.publishEvent(EventMemberLeaveAfter, &MemberLeaveAfterEventPayload{
		OrganizationID: params.OrganizationID,
		UserID:         params.UserID,
		Extra:          params.Extra,
	})

	return &LeaveOrganizationResult{Success: true}, nil
}

// ListMembers retrieves a paginated list of members belonging to the specified organization.
func (p *Plugin) ListMembers(ctx context.Context, params ListMembersParams) (*ListMembersResult, error) {
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	members, total, err := p.repo.ListMembers(ctx, params.OrganizationID, params.Limit, params.Offset)
	if err != nil {
		return nil, err
	}

	return &ListMembersResult{
		Members: members,
		Total:   total,
	}, nil
}
