package organization

import (
	"context"
	"strings"
	"time"
)

// Team Operations

// CreateTeam creates a new team within an organization after checking module enablement, limits, and RBAC permissions.
func (p *Plugin) CreateTeam(ctx context.Context, params CreateTeamParams) (*CreateTeamResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.OrganizationID == "" || strings.TrimSpace(params.Name) == "" {
		return nil, ErrInvalidParameter
	}

	// 1. RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, member.Role, Permissions{
			ResourceTeam: {ActionCreate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Check Team Limit
	if p.config.MaximumTeams != nil {
		maxTeams, err := p.config.MaximumTeams(ctx, params.OrganizationID)
		if err != nil {
			return nil, err
		}
		if maxTeams > 0 {
			count, err := p.repo.CountTeams(ctx, params.OrganizationID)
			if err != nil {
				return nil, err
			}
			if count >= maxTeams {
				return nil, ErrTeamsLimitReached
			}
		}
	}

	// 3. Emit Before Event
	p.publishEvent(EventTeamCreateBefore, &TeamCreateBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		Name:           params.Name,
		Extra:          params.Extra,
	})

	// 4. Create Team Entity
	team := &Team{
		ID:             generateRandomID("team_", 12),
		OrganizationID: params.OrganizationID,
		Name:           strings.TrimSpace(params.Name),
		CreatedAt:      time.Now(),
	}

	if err := p.repo.CreateTeam(ctx, team); err != nil {
		return nil, err
	}

	// 5. Add Creator to Team if specified
	if params.UserID != "" {
		_ = p.repo.AddTeamMember(ctx, &TeamMember{
			ID:        generateRandomID("tm_", 12),
			TeamID:    team.ID,
			UserID:    params.UserID,
			CreatedAt: time.Now(),
		})
	}

	// 6. Emit After Event
	p.publishEvent(EventTeamCreateAfter, &TeamCreateAfterEventPayload{
		Team:  team,
		Extra: params.Extra,
	})

	return &CreateTeamResult{Team: team}, nil
}

// GetTeam retrieves a team by its unique identifier.
func (p *Plugin) GetTeam(ctx context.Context, params GetTeamParams) (*GetTeamResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.TeamID == "" {
		return nil, ErrInvalidParameter
	}

	team, err := p.repo.GetTeamByID(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	return &GetTeamResult{Team: team}, nil
}

// UpdateTeam modifies properties of an existing team after verifying user permissions.
func (p *Plugin) UpdateTeam(ctx context.Context, params UpdateTeamParams) (*UpdateTeamResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.TeamID == "" || strings.TrimSpace(params.Name) == "" {
		return nil, ErrInvalidParameter
	}

	team, err := p.repo.GetTeamByID(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	// RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, team.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, team.OrganizationID, member.Role, Permissions{
			ResourceTeam: {ActionUpdate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	p.publishEvent(EventTeamUpdateBefore, &TeamUpdateBeforeEventPayload{
		TeamID: team.ID,
		Name:   params.Name,
		Extra:  params.Extra,
	})

	team.Name = strings.TrimSpace(params.Name)
	now := time.Now()
	team.UpdatedAt = &now

	if err := p.repo.UpdateTeam(ctx, team); err != nil {
		return nil, err
	}

	p.publishEvent(EventTeamUpdateAfter, &TeamUpdateAfterEventPayload{
		Team:  team,
		Extra: params.Extra,
	})

	return &UpdateTeamResult{Team: team}, nil
}

// DeleteTeam deletes a team from an organization, enforcing AllowRemovingAllTeams safety.
func (p *Plugin) DeleteTeam(ctx context.Context, params DeleteTeamParams) (*DeleteTeamResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.TeamID == "" {
		return nil, ErrInvalidParameter
	}

	team, err := p.repo.GetTeamByID(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	// RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, team.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, team.OrganizationID, member.Role, Permissions{
			ResourceTeam: {ActionDelete},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// Check if removing all teams is restricted
	if !p.config.AllowRemovingAllTeams {
		count, err := p.repo.CountTeams(ctx, team.OrganizationID)
		if err != nil {
			return nil, err
		}
		if count <= 1 {
			return nil, ErrCannotRemoveAllTeams
		}
	}

	p.publishEvent(EventTeamDeleteBefore, &TeamDeleteBeforeEventPayload{
		TeamID: team.ID,
		Extra:  params.Extra,
	})

	if err := p.repo.DeleteTeam(ctx, params.TeamID); err != nil {
		return nil, err
	}

	p.publishEvent(EventTeamDeleteAfter, &TeamDeleteAfterEventPayload{
		TeamID: team.ID,
		Extra:  params.Extra,
	})

	return &DeleteTeamResult{Success: true}, nil
}

// ListTeams retrieves all teams in an organization or all teams where a user participates.
func (p *Plugin) ListTeams(ctx context.Context, params ListTeamsParams) (*ListTeamsResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	var teams []*Team
	var err error

	if params.UserID != "" {
		teams, err = p.repo.ListTeamsByUserID(ctx, params.OrganizationID, params.UserID)
	} else {
		teams, err = p.repo.ListTeamsByOrgID(ctx, params.OrganizationID)
	}

	if err != nil {
		return nil, err
	}

	return &ListTeamsResult{Teams: teams}, nil
}

// AddTeamMember adds an existing organization member to a team after checking team member limits.
func (p *Plugin) AddTeamMember(ctx context.Context, params AddTeamMemberParams) (*AddTeamMemberResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.TeamID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	team, err := p.repo.GetTeamByID(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	// RBAC Permission Check if InvokingUserID is provided
	if params.InvokingUserID != "" {
		member, err := p.repo.GetMember(ctx, team.OrganizationID, params.InvokingUserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, team.OrganizationID, member.Role, Permissions{
			ResourceTeam: {ActionUpdate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// Verify target user is a member of the organization
	_, err = p.repo.GetMember(ctx, team.OrganizationID, params.UserID)
	if err != nil {
		return nil, ErrMemberNotFound
	}

	// Check if already a team member
	existingTM, err := p.repo.GetTeamMember(ctx, params.TeamID, params.UserID)
	if err == nil && existingTM != nil {
		return nil, ErrTeamMemberAlreadyExists
	}

	// Check team member limits
	if p.config.MaximumMembersPerTeam != nil {
		maxMembers, err := p.config.MaximumMembersPerTeam(ctx, params.TeamID)
		if err != nil {
			return nil, err
		}
		if maxMembers > 0 {
			count, err := p.repo.CountTeamMembers(ctx, params.TeamID)
			if err != nil {
				return nil, err
			}
			if count >= maxMembers {
				return nil, ErrTeamMembersLimitReached
			}
		}
	}

	p.publishEvent(EventTeamMemberAddBefore, &TeamMemberAddBeforeEventPayload{
		TeamID: params.TeamID,
		UserID: params.UserID,
		Extra:  params.Extra,
	})

	teamMember := &TeamMember{
		ID:        generateRandomID("tm_", 12),
		TeamID:    params.TeamID,
		UserID:    params.UserID,
		CreatedAt: time.Now(),
	}

	if err := p.repo.AddTeamMember(ctx, teamMember); err != nil {
		return nil, err
	}

	p.publishEvent(EventTeamMemberAddAfter, &TeamMemberAddAfterEventPayload{
		TeamMember: teamMember,
		Extra:      params.Extra,
	})

	return &AddTeamMemberResult{TeamMember: teamMember}, nil
}

// RemoveTeamMember removes a user from a team.
func (p *Plugin) RemoveTeamMember(ctx context.Context, params RemoveTeamMemberParams) (*RemoveTeamMemberResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.TeamID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	team, err := p.repo.GetTeamByID(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	// RBAC Permission Check if InvokingUserID is provided and not the user themselves
	if params.InvokingUserID != "" && params.InvokingUserID != params.UserID {
		member, err := p.repo.GetMember(ctx, team.OrganizationID, params.InvokingUserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, team.OrganizationID, member.Role, Permissions{
			ResourceTeam: {ActionUpdate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// Verify team membership
	_, err = p.repo.GetTeamMember(ctx, params.TeamID, params.UserID)
	if err != nil {
		return nil, ErrTeamMemberNotFound
	}

	p.publishEvent(EventTeamMemberRemoveBefore, &TeamMemberRemoveBeforeEventPayload{
		TeamID: params.TeamID,
		UserID: params.UserID,
		Extra:  params.Extra,
	})

	if err := p.repo.RemoveTeamMember(ctx, params.TeamID, params.UserID); err != nil {
		return nil, err
	}

	p.publishEvent(EventTeamMemberRemoveAfter, &TeamMemberRemoveAfterEventPayload{
		TeamID: params.TeamID,
		UserID: params.UserID,
		Extra:  params.Extra,
	})

	return &RemoveTeamMemberResult{Success: true}, nil
}

// ListTeamMembers retrieves all members assigned to a team.
func (p *Plugin) ListTeamMembers(ctx context.Context, params ListTeamMembersParams) (*ListTeamMembersResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.TeamID == "" {
		return nil, ErrInvalidParameter
	}

	members, err := p.repo.ListTeamMembers(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	return &ListTeamMembersResult{Members: members}, nil
}

// SetActiveTeam stores the active team context for a user in the shared context store.
func (p *Plugin) SetActiveTeam(ctx context.Context, params SetActiveTeamParams) (*SetActiveTeamResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.UserID == "" || params.TeamID == "" {
		return nil, ErrInvalidParameter
	}

	team, err := p.repo.GetTeamByID(ctx, params.TeamID)
	if err != nil {
		return nil, err
	}

	_, err = p.repo.GetTeamMember(ctx, params.TeamID, params.UserID)
	if err != nil {
		return nil, ErrTeamMemberNotFound
	}

	p.publishEvent(EventTeamSetActiveBefore, &TeamSetActiveBeforeEventPayload{
		UserID: params.UserID,
		TeamID: params.TeamID,
		Extra:  params.Extra,
	})

	if p.ctx != nil {
		p.ctx.Set(ActiveTeamContextKey(params.UserID), params.TeamID)
	}

	p.publishEvent(EventTeamSetActiveAfter, &TeamSetActiveAfterEventPayload{
		UserID: params.UserID,
		TeamID: params.TeamID,
		Team:   team,
		Extra:  params.Extra,
	})

	return &SetActiveTeamResult{Team: team}, nil
}

// GetActiveTeam retrieves the currently active team for a user.
func (p *Plugin) GetActiveTeam(ctx context.Context, params GetActiveTeamParams) (*GetActiveTeamResult, error) {
	if !p.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	var activeTeamID string
	if p.ctx != nil {
		if val, ok := p.ctx.Get(ActiveTeamContextKey(params.UserID)); ok {
			if idStr, ok := val.(string); ok {
				activeTeamID = idStr
			}
		}
	}

	if activeTeamID == "" {
		return nil, ErrTeamNotFound
	}

	team, err := p.repo.GetTeamByID(ctx, activeTeamID)
	if err != nil {
		return nil, err
	}

	return &GetActiveTeamResult{Team: team}, nil
}
