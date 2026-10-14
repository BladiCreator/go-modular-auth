package organizations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type service struct {
	ctx         *sdk.Context
	cfg         Config
	cache       *Cache
	hooks       *Hooks
	orgs        *sdk.Repository[OrganizationRecord]
	memberships *sdk.Repository[Membership]
	teams       *sdk.Repository[Team]
	teamMembers *sdk.Repository[TeamMembership]
	invitations *sdk.Repository[Invitation]
}

var _ Organization = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:         ctx,
		cfg:         cfg,
		cache:       NewCache(ctx.Cache()),
		hooks:       NewHooks(),
		orgs:        sdk.Model[OrganizationRecord](ctx, ModelOrganizations),
		memberships: sdk.Model[Membership](ctx, ModelOrganizationMemberships),
		teams:       sdk.Model[Team](ctx, ModelOrganizationTeams),
		teamMembers: sdk.Model[TeamMembership](ctx, ModelOrganizationTeamMembers),
		invitations: sdk.Model[Invitation](ctx, ModelOrganizationInvitations),
	}
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
}

func (s *service) publish(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.now(),
			Subject: subject,
			Payload: payload,
		})
	}
}

func (s *service) transaction(ctx context.Context, fn func(txCtx context.Context, tx adapter.Adapter) error) error {
	if s.ctx != nil && s.ctx.Adapter() != nil {
		return s.ctx.Adapter().Transaction(ctx, fn)
	}
	return fn(ctx, nil)
}

func validateSlug(slug string) error {
	slug = strings.TrimSpace(strings.ToLower(slug))
	if len(slug) < 2 || len(slug) > 63 || !slugRegex.MatchString(slug) {
		return fmt.Errorf("%w: invalid organization or team slug %q", ErrInvalidInput, slug)
	}
	return nil
}

func (s *service) checkPrincipalAuth(ctx context.Context, orgID string, minRole Role) error {
	principal, ok := auth.PrincipalFrom(ctx)
	if !ok || principal.Subject == "" {
		return nil
	}
	_, err := s.Authorize(ctx, orgID, minRole)
	return err
}

// CreateOrganization creates a new organization and assigns the owner as its initial member.
func (s *service) CreateOrganization(ctx context.Context, in CreateOrganizationInput) (*OrganizationRecord, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.TrimSpace(strings.ToLower(in.Slug))
	in.OwnerID = strings.TrimSpace(in.OwnerID)

	if in.Name == "" || in.OwnerID == "" {
		return nil, fmt.Errorf("%w: name and owner_id are required", ErrInvalidInput)
	}
	if err := validateSlug(in.Slug); err != nil {
		return nil, err
	}

	if err := s.hooks.runBeforeOrgCreate(ctx, &in); err != nil {
		return nil, err
	}

	now := s.now()
	org := &OrganizationRecord{
		ID:        GenerateID("org"),
		Name:      in.Name,
		Slug:      in.Slug,
		OwnerID:   in.OwnerID,
		Metadata:  in.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}

	ownerMembership := &Membership{
		ID:             GenerateID("mem"),
		OrganizationID: org.ID,
		UserID:         in.OwnerID,
		Role:           RoleOwner,
		Status:         MembershipActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	err := s.transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		txOrgs := s.orgs
		txMems := s.memberships
		if tx != nil {
			txOrgs = sdk.FromAdapter[OrganizationRecord](tx, ModelOrganizations)
			txMems = sdk.FromAdapter[Membership](tx, ModelOrganizationMemberships)
		}

		if err := txOrgs.Create(txCtx, org); err != nil {
			if errors.Is(err, adapter.ErrConflict) {
				return ErrOrganizationAlreadyExists
			}
			return err
		}
		if err := txMems.Create(txCtx, ownerMembership); err != nil {
			if errors.Is(err, adapter.ErrConflict) {
				return ErrMemberAlreadyExists
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.SetOrganization(ctx, org, s.cfg.CacheTTL)
	_ = s.cache.SetMembership(ctx, ownerMembership, s.cfg.CacheTTL)

	s.publish(ctx, EventOrganizationCreated, org.ID, OrganizationCreatedPayload{
		OrganizationID: org.ID,
		Slug:           org.Slug,
		OwnerID:        org.OwnerID,
		CreatedAt:      org.CreatedAt,
	})
	s.publish(ctx, EventMemberAdded, org.ID, MemberAddedPayload{
		OrganizationID: org.ID,
		UserID:         ownerMembership.UserID,
		Role:           ownerMembership.Role,
	})

	_ = s.hooks.runAfterOrgCreate(ctx, org)

	return org, nil
}

// GetOrganization retrieves an organization by ID.
func (s *service) GetOrganization(ctx context.Context, orgID string) (*OrganizationRecord, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("%w: empty organization id", ErrInvalidInput)
	}

	if cached, err := s.cache.GetOrganizationByID(ctx, orgID); err == nil && cached != nil {
		return cached, nil
	}

	org, err := s.orgs.FindOne(ctx, adapter.Eq("id", orgID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}

	_ = s.cache.SetOrganization(ctx, org, s.cfg.CacheTTL)
	return org, nil
}

// GetOrganizationBySlug retrieves an organization by slug.
func (s *service) GetOrganizationBySlug(ctx context.Context, slug string) (*OrganizationRecord, error) {
	slug = strings.TrimSpace(strings.ToLower(slug))
	if slug == "" {
		return nil, fmt.Errorf("%w: empty organization slug", ErrInvalidInput)
	}

	if cached, err := s.cache.GetOrganizationBySlug(ctx, slug); err == nil && cached != nil {
		return cached, nil
	}

	org, err := s.orgs.FindOne(ctx, adapter.Eq("slug", slug))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}

	_ = s.cache.SetOrganization(ctx, org, s.cfg.CacheTTL)
	return org, nil
}

// UpdateOrganization updates organization name or metadata.
func (s *service) UpdateOrganization(ctx context.Context, orgID string, in UpdateOrganizationInput) (*OrganizationRecord, error) {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleAdmin); err != nil {
		return nil, err
	}

	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}

	updates := map[string]any{}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: organization name cannot be empty", ErrInvalidInput)
		}
		org.Name = name
		updates["name"] = name
	}
	if in.Metadata != nil {
		org.Metadata = in.Metadata
		updates["metadata"] = in.Metadata
	}
	org.UpdatedAt = s.now()
	updates["updated_at"] = org.UpdatedAt

	_, err = s.orgs.Update(ctx, []adapter.Condition{adapter.Eq("id", org.ID)}, updates)
	if err != nil {
		return nil, err
	}

	_ = s.cache.DeleteOrganization(ctx, org.ID, org.Slug)
	_ = s.cache.SetOrganization(ctx, org, s.cfg.CacheTTL)

	s.publish(ctx, EventOrganizationUpdated, org.ID, OrganizationUpdatedPayload{
		OrganizationID: org.ID,
		UpdatedAt:      org.UpdatedAt,
	})

	return org, nil
}

// DeleteOrganization removes an organization and cascades to related elements.
func (s *service) DeleteOrganization(ctx context.Context, orgID string) error {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleOwner); err != nil {
		return err
	}

	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	err = s.transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		txOrgs := s.orgs
		txMems := s.memberships
		txTeams := s.teams
		txTeamMembers := s.teamMembers
		txInvs := s.invitations
		if tx != nil {
			txOrgs = sdk.FromAdapter[OrganizationRecord](tx, ModelOrganizations)
			txMems = sdk.FromAdapter[Membership](tx, ModelOrganizationMemberships)
			txTeams = sdk.FromAdapter[Team](tx, ModelOrganizationTeams)
			txTeamMembers = sdk.FromAdapter[TeamMembership](tx, ModelOrganizationTeamMembers)
			txInvs = sdk.FromAdapter[Invitation](tx, ModelOrganizationInvitations)
		}

		// Delete teams and team members
		teams, _ := txTeams.FindMany(txCtx, adapter.Query{
			Model: ModelOrganizationTeams,
			Where: []adapter.Condition{adapter.Eq("organization_id", orgID)},
		})
		for _, t := range teams {
			_, _ = txTeamMembers.Delete(txCtx, adapter.Eq("team_id", t.ID))
		}
		_, _ = txTeams.Delete(txCtx, adapter.Eq("organization_id", orgID))

		// Delete memberships
		_, _ = txMems.Delete(txCtx, adapter.Eq("organization_id", orgID))

		// Delete invitations
		_, _ = txInvs.Delete(txCtx, adapter.Eq("organization_id", orgID))

		// Delete org
		affected, err := txOrgs.Delete(txCtx, adapter.Eq("id", orgID))
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrOrganizationNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}

	_ = s.cache.DeleteOrganization(ctx, org.ID, org.Slug)

	s.publish(ctx, EventOrganizationDeleted, org.ID, OrganizationDeletedPayload{
		OrganizationID: org.ID,
		DeletedAt:      s.now(),
	})

	return nil
}

// ListUserOrganizations retrieves all organizations where user is an active member.
func (s *service) ListUserOrganizations(ctx context.Context, userID string) ([]*OrganizationRecord, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("%w: empty user id", ErrInvalidInput)
	}

	mems, err := s.memberships.FindMany(ctx, adapter.Query{
		Model: ModelOrganizationMemberships,
		Where: []adapter.Condition{
			adapter.Eq("user_id", userID),
			adapter.Eq("status", string(MembershipActive)),
		},
	})
	if err != nil {
		return nil, err
	}

	var res []*OrganizationRecord
	for _, m := range mems {
		org, err := s.GetOrganization(ctx, m.OrganizationID)
		if err == nil && org != nil {
			res = append(res, org)
		}
	}
	return res, nil
}

// TransferOwnership transfers ownership to an existing active member.
func (s *service) TransferOwnership(ctx context.Context, orgID, newOwnerUserID string) error {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleOwner); err != nil {
		return err
	}

	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	newOwnerUserID = strings.TrimSpace(newOwnerUserID)
	if newOwnerUserID == "" || newOwnerUserID == org.OwnerID {
		return fmt.Errorf("%w: invalid target owner", ErrInvalidInput)
	}

	newOwnerMem, err := s.GetMember(ctx, orgID, newOwnerUserID)
	if err != nil {
		return err
	}
	if !newOwnerMem.Active() {
		return fmt.Errorf("%w: new owner must be an active member", ErrInvalidInput)
	}

	oldOwnerMem, err := s.GetMember(ctx, orgID, org.OwnerID)
	if err != nil {
		return err
	}

	now := s.now()
	err = s.transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		txOrgs := s.orgs
		txMems := s.memberships
		if tx != nil {
			txOrgs = sdk.FromAdapter[OrganizationRecord](tx, ModelOrganizations)
			txMems = sdk.FromAdapter[Membership](tx, ModelOrganizationMemberships)
		}

		oldOwnerMem.Role = RoleAdmin
		oldOwnerMem.UpdatedAt = now
		_, err := txMems.Update(txCtx, []adapter.Condition{adapter.Eq("id", oldOwnerMem.ID)}, map[string]any{
			"role":       string(RoleAdmin),
			"updated_at": now,
		})
		if err != nil {
			return err
		}

		newOwnerMem.Role = RoleOwner
		newOwnerMem.UpdatedAt = now
		_, err = txMems.Update(txCtx, []adapter.Condition{adapter.Eq("id", newOwnerMem.ID)}, map[string]any{
			"role":       string(RoleOwner),
			"updated_at": now,
		})
		if err != nil {
			return err
		}

		org.OwnerID = newOwnerUserID
		org.UpdatedAt = now
		_, err = txOrgs.Update(txCtx, []adapter.Condition{adapter.Eq("id", org.ID)}, map[string]any{
			"owner_id":   newOwnerUserID,
			"updated_at": now,
		})
		return err
	})
	if err != nil {
		return err
	}

	_ = s.cache.DeleteOrganization(ctx, org.ID, org.Slug)
	_ = s.cache.DeleteMembership(ctx, orgID, oldOwnerMem.UserID)
	_ = s.cache.DeleteMembership(ctx, orgID, newOwnerMem.UserID)

	s.publish(ctx, EventOwnershipTransferred, org.ID, OwnershipTransferredPayload{
		OrganizationID: org.ID,
		OldOwnerID:     oldOwnerMem.UserID,
		NewOwnerID:     newOwnerUserID,
	})

	return nil
}

// AddMember associates a user with the organization.
func (s *service) AddMember(ctx context.Context, in AddMemberInput) (*Membership, error) {
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.UserID = strings.TrimSpace(in.UserID)
	if in.OrganizationID == "" || in.UserID == "" {
		return nil, fmt.Errorf("%w: organization_id and user_id are required", ErrInvalidInput)
	}
	if in.Role == "" {
		in.Role = RoleMember
	}

	if err := s.checkPrincipalAuth(ctx, in.OrganizationID, RoleAdmin); err != nil {
		return nil, err
	}

	if err := s.hooks.runBeforeMemberAdd(ctx, &in); err != nil {
		return nil, err
	}

	now := s.now()
	m := &Membership{
		ID:             GenerateID("mem"),
		OrganizationID: in.OrganizationID,
		UserID:         in.UserID,
		Role:           in.Role,
		Status:         MembershipActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.memberships.Create(ctx, m); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return nil, ErrMemberAlreadyExists
		}
		return nil, err
	}

	_ = s.cache.SetMembership(ctx, m, s.cfg.CacheTTL)

	s.publish(ctx, EventMemberAdded, in.OrganizationID, MemberAddedPayload{
		OrganizationID: in.OrganizationID,
		UserID:         in.UserID,
		Role:           in.Role,
	})

	_ = s.hooks.runAfterMemberAdd(ctx, m)

	return m, nil
}

// GetMember retrieves a membership record.
func (s *service) GetMember(ctx context.Context, orgID, userID string) (*Membership, error) {
	orgID = strings.TrimSpace(orgID)
	userID = strings.TrimSpace(userID)
	if orgID == "" || userID == "" {
		return nil, fmt.Errorf("%w: organization_id and user_id are required", ErrInvalidInput)
	}

	if cached, err := s.cache.GetMembership(ctx, orgID, userID); err == nil && cached != nil {
		return cached, nil
	}

	m, err := s.memberships.FindOne(ctx, adapter.Eq("organization_id", orgID), adapter.Eq("user_id", userID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, err
	}

	_ = s.cache.SetMembership(ctx, m, s.cfg.CacheTTL)
	return m, nil
}

// UpdateMemberRole updates the role assigned to a member.
func (s *service) UpdateMemberRole(ctx context.Context, orgID, userID string, role Role) (*Membership, error) {
	if principal, ok := auth.PrincipalFrom(ctx); ok && principal.Subject != "" {
		minRole := RoleAdmin
		if role == RoleOwner {
			minRole = RoleOwner
		}
		callerMem, err := s.Authorize(ctx, orgID, minRole)
		if err != nil {
			return nil, err
		}
		targetMem, err := s.GetMember(ctx, orgID, userID)
		if err == nil && targetMem.Role == RoleOwner && callerMem.Role != RoleOwner {
			return nil, ErrUnauthorized
		}
	}

	m, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && role != RoleOwner {
		return nil, ErrCannotRemoveOwner
	}

	now := s.now()
	m.Role = role
	m.UpdatedAt = now

	_, err = s.memberships.Update(ctx, []adapter.Condition{adapter.Eq("id", m.ID)}, map[string]any{
		"role":       string(role),
		"updated_at": now,
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.DeleteMembership(ctx, orgID, userID)
	_ = s.cache.SetMembership(ctx, m, s.cfg.CacheTTL)

	s.publish(ctx, EventMemberUpdated, orgID, MemberUpdatedPayload{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           m.Role,
		Status:         m.Status,
	})

	return m, nil
}

// UpdateMemberStatus updates the membership status (active/suspended).
func (s *service) UpdateMemberStatus(ctx context.Context, orgID, userID string, status MembershipStatus) (*Membership, error) {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleAdmin); err != nil {
		return nil, err
	}

	m, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && status != MembershipActive {
		return nil, ErrCannotRemoveOwner
	}

	now := s.now()
	m.Status = status
	m.UpdatedAt = now

	_, err = s.memberships.Update(ctx, []adapter.Condition{adapter.Eq("id", m.ID)}, map[string]any{
		"status":     string(status),
		"updated_at": now,
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.DeleteMembership(ctx, orgID, userID)
	_ = s.cache.SetMembership(ctx, m, s.cfg.CacheTTL)

	s.publish(ctx, EventMemberUpdated, orgID, MemberUpdatedPayload{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           m.Role,
		Status:         m.Status,
	})

	return m, nil
}

// RemoveMember removes a user from an organization.
func (s *service) RemoveMember(ctx context.Context, orgID, userID string) error {
	orgID = strings.TrimSpace(orgID)
	userID = strings.TrimSpace(userID)
	if orgID == "" || userID == "" {
		return fmt.Errorf("%w: organization_id and user_id are required", ErrInvalidInput)
	}

	if principal, ok := auth.PrincipalFrom(ctx); ok && principal.Subject != "" {
		if principal.Subject != userID {
			if _, err := s.Authorize(ctx, orgID, RoleAdmin); err != nil {
				return err
			}
		} else {
			if _, err := s.Authorize(ctx, orgID, RoleMember); err != nil {
				return err
			}
		}
	}

	m, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return err
	}

	if m.Role == RoleOwner {
		return ErrCannotRemoveOwner
	}

	affected, err := s.memberships.Delete(ctx, adapter.Eq("organization_id", orgID), adapter.Eq("user_id", userID))
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrMemberNotFound
	}

	_ = s.cache.DeleteMembership(ctx, orgID, userID)

	s.publish(ctx, EventMemberRemoved, orgID, MemberRemovedPayload{
		OrganizationID: orgID,
		UserID:         userID,
	})

	return nil
}

// ListMembers retrieves all members of an organization.
func (s *service) ListMembers(ctx context.Context, orgID string) ([]*Membership, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("%w: organization_id is required", ErrInvalidInput)
	}

	rows, err := s.memberships.FindMany(ctx, adapter.Query{
		Model: ModelOrganizationMemberships,
		Where: []adapter.Condition{adapter.Eq("organization_id", orgID)},
	})
	if err != nil {
		return nil, err
	}

	res := make([]*Membership, len(rows))
	for i := range rows {
		res[i] = &rows[i]
	}
	return res, nil
}

// CreateTeam creates a new team inside an organization.
func (s *service) CreateTeam(ctx context.Context, in CreateTeamInput) (*Team, error) {
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.TrimSpace(strings.ToLower(in.Slug))

	if in.OrganizationID == "" || in.Name == "" {
		return nil, fmt.Errorf("%w: organization_id and name are required", ErrInvalidInput)
	}
	if err := validateSlug(in.Slug); err != nil {
		return nil, err
	}
	if err := s.checkPrincipalAuth(ctx, in.OrganizationID, RoleAdmin); err != nil {
		return nil, err
	}

	now := s.now()
	t := &Team{
		ID:             GenerateID("team"),
		OrganizationID: in.OrganizationID,
		Name:           in.Name,
		Slug:           in.Slug,
		Description:    in.Description,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.teams.Create(ctx, t); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return nil, ErrTeamAlreadyExists
		}
		return nil, err
	}

	s.publish(ctx, EventTeamCreated, in.OrganizationID, TeamCreatedPayload{
		OrganizationID: in.OrganizationID,
		TeamID:         t.ID,
		Slug:           t.Slug,
	})

	return t, nil
}

// GetTeam retrieves a team by ID within the organization.
func (s *service) GetTeam(ctx context.Context, orgID, teamID string) (*Team, error) {
	t, err := s.teams.FindOne(ctx, adapter.Eq("organization_id", orgID), adapter.Eq("id", teamID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrTeamNotFound
		}
		return nil, err
	}
	return t, nil
}

// UpdateTeam updates team details.
func (s *service) UpdateTeam(ctx context.Context, orgID, teamID string, in UpdateTeamInput) (*Team, error) {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleAdmin); err != nil {
		return nil, err
	}

	t, err := s.GetTeam(ctx, orgID, teamID)
	if err != nil {
		return nil, err
	}

	updates := map[string]any{}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: team name cannot be empty", ErrInvalidInput)
		}
		t.Name = name
		updates["name"] = name
	}
	if in.Description != nil {
		t.Description = *in.Description
		updates["description"] = *in.Description
	}
	t.UpdatedAt = s.now()
	updates["updated_at"] = t.UpdatedAt

	_, err = s.teams.Update(ctx, []adapter.Condition{
		adapter.Eq("organization_id", orgID),
		adapter.Eq("id", teamID),
	}, updates)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, EventTeamUpdated, orgID, TeamUpdatedPayload{
		OrganizationID: orgID,
		TeamID:         teamID,
	})

	return t, nil
}

// DeleteTeam deletes a team.
func (s *service) DeleteTeam(ctx context.Context, orgID, teamID string) error {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleAdmin); err != nil {
		return err
	}

	if _, err := s.GetTeam(ctx, orgID, teamID); err != nil {
		return err
	}

	err := s.transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		txTeams := s.teams
		txTeamMembers := s.teamMembers
		if tx != nil {
			txTeams = sdk.FromAdapter[Team](tx, ModelOrganizationTeams)
			txTeamMembers = sdk.FromAdapter[TeamMembership](tx, ModelOrganizationTeamMembers)
		}

		_, _ = txTeamMembers.Delete(txCtx, adapter.Eq("team_id", teamID))
		affected, err := txTeams.Delete(txCtx, adapter.Eq("organization_id", orgID), adapter.Eq("id", teamID))
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrTeamNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.publish(ctx, EventTeamDeleted, orgID, TeamDeletedPayload{
		OrganizationID: orgID,
		TeamID:         teamID,
	})

	return nil
}

// ListTeams lists all teams in an organization.
func (s *service) ListTeams(ctx context.Context, orgID string) ([]*Team, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("%w: organization_id is required", ErrInvalidInput)
	}

	rows, err := s.teams.FindMany(ctx, adapter.Query{
		Model: ModelOrganizationTeams,
		Where: []adapter.Condition{adapter.Eq("organization_id", orgID)},
	})
	if err != nil {
		return nil, err
	}

	res := make([]*Team, len(rows))
	for i := range rows {
		res[i] = &rows[i]
	}
	return res, nil
}

// AddTeamMember enrolls a member into a team, ensuring they belong to the organization.
func (s *service) AddTeamMember(ctx context.Context, orgID, teamID, userID string) error {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleAdmin); err != nil {
		return err
	}

	if _, err := s.GetTeam(ctx, orgID, teamID); err != nil {
		return err
	}

	// Verify the user is an active member of this organization
	mem, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if !mem.Active() {
		return fmt.Errorf("%w: member is not active", ErrUnauthorized)
	}

	tm := &TeamMembership{
		ID:        teamID + ":" + userID,
		TeamID:    teamID,
		UserID:    userID,
		CreatedAt: s.now(),
	}

	if err := s.teamMembers.Create(ctx, tm); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return ErrTeamMemberAlreadyExists
		}
		return err
	}

	s.publish(ctx, EventTeamMemberAdded, orgID, TeamMemberPayload{
		OrganizationID: orgID,
		TeamID:         teamID,
		UserID:         userID,
	})

	return nil
}

// RemoveTeamMember removes a user from a team.
func (s *service) RemoveTeamMember(ctx context.Context, orgID, teamID, userID string) error {
	if principal, ok := auth.PrincipalFrom(ctx); ok && principal.Subject != "" {
		if principal.Subject != userID {
			if _, err := s.Authorize(ctx, orgID, RoleAdmin); err != nil {
				return err
			}
		} else {
			if _, err := s.Authorize(ctx, orgID, RoleMember); err != nil {
				return err
			}
		}
	}

	if _, err := s.GetTeam(ctx, orgID, teamID); err != nil {
		return err
	}

	affected, err := s.teamMembers.Delete(ctx, adapter.Eq("team_id", teamID), adapter.Eq("user_id", userID))
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrTeamMemberNotFound
	}

	s.publish(ctx, EventTeamMemberRemoved, orgID, TeamMemberPayload{
		OrganizationID: orgID,
		TeamID:         teamID,
		UserID:         userID,
	})

	return nil
}

// ListTeamMembers lists all user IDs in a team.
func (s *service) ListTeamMembers(ctx context.Context, orgID, teamID string) ([]string, error) {
	if _, err := s.GetTeam(ctx, orgID, teamID); err != nil {
		return nil, err
	}

	rows, err := s.teamMembers.FindMany(ctx, adapter.Query{
		Model: ModelOrganizationTeamMembers,
		Where: []adapter.Condition{adapter.Eq("team_id", teamID)},
	})
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, len(rows))
	for i, r := range rows {
		userIDs[i] = r.UserID
	}
	return userIDs, nil
}

// CreateInvitation generates an invitation and plaintext secret token.
func (s *service) CreateInvitation(ctx context.Context, in CreateInvitationInput) (*Invitation, string, error) {
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	in.InviterUserID = strings.TrimSpace(in.InviterUserID)

	if in.OrganizationID == "" || in.Email == "" || in.InviterUserID == "" {
		return nil, "", fmt.Errorf("%w: organization_id, email, and inviter_user_id are required", ErrInvalidInput)
	}
	if err := s.checkPrincipalAuth(ctx, in.OrganizationID, RoleAdmin); err != nil {
		return nil, "", err
	}
	if in.Role == "" {
		in.Role = RoleMember
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = s.cfg.DefaultInvitationTTL
	}

	rawToken, err := GenerateToken()
	if err != nil {
		return nil, "", err
	}
	tokenHash := HashToken(rawToken)

	now := s.now()
	inv := &Invitation{
		ID:             GenerateID("inv"),
		OrganizationID: in.OrganizationID,
		Email:          in.Email,
		Role:           in.Role,
		InviterUserID:  in.InviterUserID,
		TokenHash:      tokenHash,
		ExpiresAt:      now.Add(ttl),
		CreatedAt:      now,
	}

	if err := s.invitations.Create(ctx, inv); err != nil {
		return nil, "", err
	}

	s.publish(ctx, EventInvitationCreated, in.OrganizationID, InvitationCreatedPayload{
		OrganizationID: in.OrganizationID,
		InvitationID:   inv.ID,
		Email:          inv.Email,
		Role:           inv.Role,
		InviterUserID:  in.InviterUserID,
		ExpiresAt:      inv.ExpiresAt,
	})

	return inv, rawToken, nil
}

// GetInvitation retrieves an invitation by ID within an organization.
func (s *service) GetInvitation(ctx context.Context, orgID, invitationID string) (*Invitation, error) {
	inv, err := s.invitations.FindOne(ctx, adapter.Eq("organization_id", orgID), adapter.Eq("id", invitationID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrInvitationNotFound
		}
		return nil, err
	}
	return inv, nil
}

// ListInvitations lists pending invitations for an organization.
func (s *service) ListInvitations(ctx context.Context, orgID string) ([]*Invitation, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("%w: organization_id is required", ErrInvalidInput)
	}

	rows, err := s.invitations.FindMany(ctx, adapter.Query{
		Model: ModelOrganizationInvitations,
		Where: []adapter.Condition{adapter.Eq("organization_id", orgID)},
	})
	if err != nil {
		return nil, err
	}

	res := make([]*Invitation, len(rows))
	for i := range rows {
		res[i] = &rows[i]
	}
	return res, nil
}

// AcceptInvitation validates token and redeems invitation atomically.
func (s *service) AcceptInvitation(ctx context.Context, rawToken, userID string) (*Membership, error) {
	rawToken = strings.TrimSpace(rawToken)
	userID = strings.TrimSpace(userID)
	if rawToken == "" || userID == "" {
		return nil, fmt.Errorf("%w: token and user_id are required", ErrInvalidInput)
	}

	tokenHash := HashToken(rawToken)
	now := s.now()

	var m *Membership
	var orgID string
	var invID string

	err := s.transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		txInvs := s.invitations
		txMems := s.memberships
		if tx != nil {
			txInvs = sdk.FromAdapter[Invitation](tx, ModelOrganizationInvitations)
			txMems = sdk.FromAdapter[Membership](tx, ModelOrganizationMemberships)
		}

		inv, err := txInvs.FindOne(txCtx, adapter.Eq("token_hash", tokenHash))
		if err != nil {
			if errors.Is(err, adapter.ErrNotFound) {
				return ErrInvitationNotFound
			}
			return err
		}

		if inv.Accepted() {
			return ErrInvitationAlreadyAccepted
		}
		if inv.Expired(now) {
			return ErrInvitationExpired
		}

		// Verify not already member
		if existingMem, _ := txMems.FindOne(txCtx, adapter.Eq("organization_id", inv.OrganizationID), adapter.Eq("user_id", userID)); existingMem != nil {
			return ErrMemberAlreadyExists
		}

		inv.AcceptedAt = &now
		_, err = txInvs.Update(txCtx, []adapter.Condition{adapter.Eq("id", inv.ID)}, map[string]any{
			"accepted_at": now,
		})
		if err != nil {
			return err
		}

		m = &Membership{
			ID:             GenerateID("mem"),
			OrganizationID: inv.OrganizationID,
			UserID:         userID,
			Role:           inv.Role,
			Status:         MembershipActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		orgID = inv.OrganizationID
		invID = inv.ID

		return txMems.Create(txCtx, m)
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.SetMembership(ctx, m, s.cfg.CacheTTL)

	s.publish(ctx, EventInvitationAccepted, orgID, InvitationAcceptedPayload{
		OrganizationID: orgID,
		InvitationID:   invID,
		UserID:         userID,
		AcceptedAt:     now,
	})
	s.publish(ctx, EventMemberAdded, orgID, MemberAddedPayload{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           m.Role,
	})

	return m, nil
}

// RevokeInvitation cancels an active invitation.
func (s *service) RevokeInvitation(ctx context.Context, orgID, invitationID string) error {
	if err := s.checkPrincipalAuth(ctx, orgID, RoleAdmin); err != nil {
		return err
	}

	if _, err := s.GetInvitation(ctx, orgID, invitationID); err != nil {
		return err
	}

	affected, err := s.invitations.Delete(ctx, adapter.Eq("organization_id", orgID), adapter.Eq("id", invitationID))
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrInvitationNotFound
	}

	s.publish(ctx, EventInvitationRevoked, orgID, InvitationRevokedPayload{
		OrganizationID: orgID,
		InvitationID:   invitationID,
	})

	return nil
}

// Authorize verifies that the request Principal has at least minRole in orgID.
func (s *service) Authorize(ctx context.Context, orgID string, minRole Role) (*Membership, error) {
	principal, ok := auth.PrincipalFrom(ctx)
	if !ok || principal.Subject == "" {
		return nil, ErrUnauthorized
	}

	// Verify contextual tenant consistency (prevent cross-organization access)
	if boundOrg, ok := OrganizationFromContext(ctx); ok && boundOrg != orgID {
		return nil, ErrCrossOrganizationAccess
	}

	mem, err := s.GetMember(ctx, orgID, principal.Subject)
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}

	if !mem.Active() {
		return nil, ErrUnauthorized
	}

	if !mem.Role.AtLeast(minRole) {
		return nil, ErrUnauthorized
	}

	return mem, nil
}
