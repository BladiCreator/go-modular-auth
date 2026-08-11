package organization

import (
	"context"
	"strings"
	"time"
)

// Invitation Operations

// CreateInvitation generates a new pending invitation for a target email address, enforcing invitation limits,
// checking authorization permissions, calculating expiration, and optionally dispatching an email notification.
func (p *Plugin) CreateInvitation(ctx context.Context, params CreateInvitationParams) (*CreateInvitationResult, error) {
	if params.OrganizationID == "" || params.InviterID == "" || strings.TrimSpace(params.Email) == "" {
		return nil, ErrInvalidParameter
	}

	email := strings.ToLower(strings.TrimSpace(params.Email))
	role := params.Role
	if strings.TrimSpace(role) == "" {
		role = RoleMember
	}

	// 1. RBAC Permission Check
	inviter, err := p.repo.GetMember(ctx, params.OrganizationID, params.InviterID)
	if err != nil {
		return nil, ErrPermissionDenied
	}
	allowed, err := p.CheckPermission(ctx, params.OrganizationID, inviter.Role, Permissions{
		ResourceInvitation: {ActionCreate},
	})
	if err != nil || !allowed {
		return nil, ErrPermissionDenied
	}

	// 2. Check Invitation Limits
	if p.config.InvitationLimit != nil {
		maxInvitations, err := p.config.InvitationLimit(ctx, params.OrganizationID)
		if err != nil {
			return nil, err
		}
		if maxInvitations > 0 {
			count, err := p.repo.CountPendingInvitations(ctx, params.OrganizationID)
			if err != nil {
				return nil, err
			}
			if count >= maxInvitations {
				return nil, ErrInvitationLimitReached
			}
		}
	}

	// 3. Check for existing pending invitation
	existing, err := p.repo.GetPendingInvitation(ctx, params.OrganizationID, email)
	if err == nil && existing != nil && time.Now().Before(existing.ExpiresAt) {
		if p.config.CancelPendingInvitationsOnReInvite {
			existing.Status = InvitationStatusCanceled
			_ = p.repo.UpdateInvitation(ctx, existing)
		} else {
			return nil, ErrInvitationAlreadyExists
		}
	}

	// 4. Calculate Expiration
	expiresIn := p.config.InvitationExpiresIn
	if expiresIn <= 0 {
		expiresIn = 48 * time.Hour
	}
	expiresAt := time.Now().Add(expiresIn)

	// 5. Emit Before Event
	p.publishEvent(EventInvitationCreateBefore, &InvitationCreateBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		InviterID:      params.InviterID,
		Email:          email,
		Role:           role,
		TeamID:         params.TeamID,
		Extra:          params.Extra,
	})

	// 6. Create Invitation Entity
	invitation := &Invitation{
		ID:             generateRandomID("inv_", 12),
		OrganizationID: params.OrganizationID,
		Email:          email,
		Role:           role,
		Status:         InvitationStatusPending,
		TeamID:         params.TeamID,
		InviterID:      params.InviterID,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now(),
	}

	if err := p.repo.CreateInvitation(ctx, invitation); err != nil {
		return nil, err
	}

	// 7. Dispatch Invitation Email Callback if configured
	if p.config.SendInvitationEmail != nil {
		org, _ := p.repo.GetOrganizationByID(ctx, params.OrganizationID)
		_ = p.config.SendInvitationEmail(ctx, InvitationEmailData{
			Invitation:   invitation,
			Organization: org,
			InviterID:    params.InviterID,
		})
	}

	// 8. Emit After Event
	p.publishEvent(EventInvitationCreateAfter, &InvitationCreateAfterEventPayload{
		Invitation: invitation,
		Extra:      params.Extra,
	})

	return &CreateInvitationResult{Invitation: invitation}, nil
}

// GetInvitation retrieves an invitation by its unique identifier.
func (p *Plugin) GetInvitation(ctx context.Context, params GetInvitationParams) (*GetInvitationResult, error) {
	if params.InvitationID == "" {
		return nil, ErrInvalidParameter
	}

	invitation, err := p.repo.GetInvitationByID(ctx, params.InvitationID)
	if err != nil {
		return nil, err
	}

	return &GetInvitationResult{Invitation: invitation}, nil
}

// AcceptInvitation accepts an active pending invitation, creates a new membership record, assigns team if specified, and marks the invitation accepted.
func (p *Plugin) AcceptInvitation(ctx context.Context, params AcceptInvitationParams) (*AcceptInvitationResult, error) {
	if params.InvitationID == "" || params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	// 1. Fetch Invitation
	invitation, err := p.repo.GetInvitationByID(ctx, params.InvitationID)
	if err != nil {
		return nil, err
	}

	if invitation.Status != InvitationStatusPending {
		return nil, ErrInvalidInvitationStatus
	}

	if time.Now().After(invitation.ExpiresAt) {
		return nil, ErrInvitationExpired
	}

	// 2. Fetch Organization
	org, err := p.repo.GetOrganizationByID(ctx, invitation.OrganizationID)
	if err != nil {
		return nil, err
	}

	// 3. Check if user is already a member
	existingMember, err := p.repo.GetMember(ctx, invitation.OrganizationID, params.UserID)
	if err == nil && existingMember != nil {
		return nil, ErrMemberAlreadyExists
	}

	// 4. Check Membership Limit
	if p.config.MembershipLimit != nil {
		maxMembers, err := p.config.MembershipLimit(ctx, invitation.OrganizationID)
		if err != nil {
			return nil, err
		}
		if maxMembers > 0 {
			count, err := p.repo.CountMembers(ctx, invitation.OrganizationID)
			if err != nil {
				return nil, err
			}
			if count >= maxMembers {
				return nil, ErrMembershipLimitReached
			}
		}
	}

	// 5. Emit Before Event
	p.publishEvent(EventInvitationAcceptBefore, &InvitationAcceptBeforeEventPayload{
		InvitationID: params.InvitationID,
		UserID:       params.UserID,
		Extra:        params.Extra,
	})

	// 6. Update Invitation Status
	invitation.Status = InvitationStatusAccepted
	if err := p.repo.UpdateInvitation(ctx, invitation); err != nil {
		return nil, err
	}

	// 7. Create Member Record
	member := &Member{
		ID:             generateRandomID("mem_", 12),
		OrganizationID: invitation.OrganizationID,
		UserID:         params.UserID,
		Role:           invitation.Role,
		CreatedAt:      time.Now(),
	}

	if err := p.repo.CreateMember(ctx, member); err != nil {
		return nil, err
	}

	// 8. Associate with Team if specified
	if invitation.TeamID != nil && *invitation.TeamID != "" && p.config.TeamsEnabled {
		_ = p.repo.AddTeamMember(ctx, &TeamMember{
			ID:        generateRandomID("tm_", 12),
			TeamID:    *invitation.TeamID,
			UserID:    params.UserID,
			CreatedAt: time.Now(),
		})
	}

	// 9. Emit After Event
	p.publishEvent(EventInvitationAcceptAfter, &InvitationAcceptAfterEventPayload{
		Invitation:   invitation,
		Member:       member,
		Organization: org,
		Extra:        params.Extra,
	})

	return &AcceptInvitationResult{
		Invitation:   invitation,
		Member:       member,
		Organization: org,
	}, nil
}

// RejectInvitation marks a pending invitation as rejected.
func (p *Plugin) RejectInvitation(ctx context.Context, params RejectInvitationParams) (*RejectInvitationResult, error) {
	if params.InvitationID == "" {
		return nil, ErrInvalidParameter
	}

	invitation, err := p.repo.GetInvitationByID(ctx, params.InvitationID)
	if err != nil {
		return nil, err
	}

	if invitation.Status != InvitationStatusPending {
		return nil, ErrInvalidInvitationStatus
	}

	p.publishEvent(EventInvitationRejectBefore, &InvitationRejectBeforeEventPayload{
		InvitationID: params.InvitationID,
		UserID:       params.UserID,
		Extra:        params.Extra,
	})

	invitation.Status = InvitationStatusRejected
	if err := p.repo.UpdateInvitation(ctx, invitation); err != nil {
		return nil, err
	}

	p.publishEvent(EventInvitationRejectAfter, &InvitationRejectAfterEventPayload{
		Invitation: invitation,
		Extra:      params.Extra,
	})

	return &RejectInvitationResult{Invitation: invitation}, nil
}

// CancelInvitation cancels a pending invitation after verifying user cancellation permissions.
func (p *Plugin) CancelInvitation(ctx context.Context, params CancelInvitationParams) (*CancelInvitationResult, error) {
	if params.InvitationID == "" {
		return nil, ErrInvalidParameter
	}

	invitation, err := p.repo.GetInvitationByID(ctx, params.InvitationID)
	if err != nil {
		return nil, err
	}

	if invitation.Status != InvitationStatusPending {
		return nil, ErrInvalidInvitationStatus
	}

	// RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		invoker, err := p.repo.GetMember(ctx, invitation.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, invitation.OrganizationID, invoker.Role, Permissions{
			ResourceInvitation: {ActionCancel},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	p.publishEvent(EventInvitationCancelBefore, &InvitationCancelBeforeEventPayload{
		InvitationID: params.InvitationID,
		UserID:       params.UserID,
		Extra:        params.Extra,
	})

	invitation.Status = InvitationStatusCanceled
	if err := p.repo.UpdateInvitation(ctx, invitation); err != nil {
		return nil, err
	}

	p.publishEvent(EventInvitationCancelAfter, &InvitationCancelAfterEventPayload{
		Invitation: invitation,
		Extra:      params.Extra,
	})

	return &CancelInvitationResult{Invitation: invitation}, nil
}

// ListInvitations retrieves all invitations for an organization, optionally filtered by status.
func (p *Plugin) ListInvitations(ctx context.Context, params ListInvitationsParams) (*ListInvitationsResult, error) {
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	invitations, err := p.repo.ListInvitationsByOrgID(ctx, params.OrganizationID, params.Status)
	if err != nil {
		return nil, err
	}

	return &ListInvitationsResult{Invitations: invitations}, nil
}

// ListUserInvitations retrieves all invitations targeted to a given email address.
func (p *Plugin) ListUserInvitations(ctx context.Context, params ListUserInvitationsParams) (*ListUserInvitationsResult, error) {
	if strings.TrimSpace(params.Email) == "" {
		return nil, ErrInvalidParameter
	}

	email := strings.ToLower(strings.TrimSpace(params.Email))
	invitations, err := p.repo.ListInvitationsByEmail(ctx, email, params.Status)
	if err != nil {
		return nil, err
	}

	return &ListUserInvitationsResult{Invitations: invitations}, nil
}
