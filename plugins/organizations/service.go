package organizations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-organizations/cache"
	"github.com/BladiCreator/go-modular-auth-organizations/store"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type service struct {
	ctx   *sdk.Context
	cfg   Config
	cache *cache.Cache
	hooks *Hooks
}

var _ Organization = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:   ctx,
		cfg:   cfg,
		cache: cache.New(ctx.Cache()),
		hooks: NewHooks(),
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

func validateSlug(slug string) error {
	slug = strings.TrimSpace(strings.ToLower(slug))
	if len(slug) < 2 || len(slug) > 63 || !slugRegex.MatchString(slug) {
		return fmt.Errorf("%w: invalid organization or team slug %q", ErrInvalidInput, slug)
	}
	return nil
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

	err := s.cfg.Store.Transaction(ctx, func(txCtx context.Context) error {
		if err := s.cfg.Store.CreateOrganization(txCtx, org); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrOrganizationAlreadyExists
			}
			return err
		}
		if err := s.cfg.Store.CreateMembership(txCtx, ownerMembership); err != nil {
			if errors.Is(err, store.ErrConflict) {
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

	org, err := s.cfg.Store.GetOrganizationByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
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

	org, err := s.cfg.Store.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, err
	}

	_ = s.cache.SetOrganization(ctx, org, s.cfg.CacheTTL)
	return org, nil
}

// UpdateOrganization updates organization name or metadata.
func (s *service) UpdateOrganization(ctx context.Context, orgID string, in UpdateOrganizationInput) (*OrganizationRecord, error) {
	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}

	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: organization name cannot be empty", ErrInvalidInput)
		}
		org.Name = name
	}
	if in.Metadata != nil {
		org.Metadata = in.Metadata
	}
	org.UpdatedAt = s.now()

	if err := s.cfg.Store.UpdateOrganization(ctx, org); err != nil {
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
	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		return err
	}

	if err := s.cfg.Store.DeleteOrganization(ctx, orgID); err != nil {
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
	return s.cfg.Store.ListOrganizationsByUser(ctx, userID)
}

// TransferOwnership transfers ownership to an existing active member.
func (s *service) TransferOwnership(ctx context.Context, orgID, newOwnerUserID string) error {
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
	err = s.cfg.Store.Transaction(ctx, func(txCtx context.Context) error {
		oldOwnerMem.Role = RoleAdmin
		oldOwnerMem.UpdatedAt = now
		if err := s.cfg.Store.UpdateMembership(txCtx, oldOwnerMem); err != nil {
			return err
		}

		newOwnerMem.Role = RoleOwner
		newOwnerMem.UpdatedAt = now
		if err := s.cfg.Store.UpdateMembership(txCtx, newOwnerMem); err != nil {
			return err
		}

		org.OwnerID = newOwnerUserID
		org.UpdatedAt = now
		return s.cfg.Store.UpdateOrganization(txCtx, org)
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

	if err := s.cfg.Store.CreateMembership(ctx, m); err != nil {
		if errors.Is(err, store.ErrConflict) {
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

	m, err := s.cfg.Store.GetMembership(ctx, orgID, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, err
	}

	_ = s.cache.SetMembership(ctx, m, s.cfg.CacheTTL)
	return m, nil
}

// UpdateMemberRole updates the role assigned to a member.
func (s *service) UpdateMemberRole(ctx context.Context, orgID, userID string, role Role) (*Membership, error) {
	m, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && role != RoleOwner {
		return nil, ErrCannotRemoveOwner
	}

	m.Role = role
	m.UpdatedAt = s.now()

	if err := s.cfg.Store.UpdateMembership(ctx, m); err != nil {
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
	m, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && status != MembershipActive {
		return nil, ErrCannotRemoveOwner
	}

	m.Status = status
	m.UpdatedAt = s.now()

	if err := s.cfg.Store.UpdateMembership(ctx, m); err != nil {
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
	m, err := s.GetMember(ctx, orgID, userID)
	if err != nil {
		return err
	}

	if m.Role == RoleOwner {
		return ErrCannotRemoveOwner
	}

	if err := s.cfg.Store.DeleteMembership(ctx, orgID, userID); err != nil {
		return err
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
	return s.cfg.Store.ListMembershipsByOrg(ctx, orgID)
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

	if err := s.cfg.Store.CreateTeam(ctx, t); err != nil {
		if errors.Is(err, store.ErrConflict) {
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
	t, err := s.cfg.Store.GetTeamByID(ctx, orgID, teamID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrTeamNotFound
		}
		return nil, err
	}
	return t, nil
}

// UpdateTeam updates team details.
func (s *service) UpdateTeam(ctx context.Context, orgID, teamID string, in UpdateTeamInput) (*Team, error) {
	t, err := s.GetTeam(ctx, orgID, teamID)
	if err != nil {
		return nil, err
	}

	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: team name cannot be empty", ErrInvalidInput)
		}
		t.Name = name
	}
	if in.Description != nil {
		t.Description = *in.Description
	}
	t.UpdatedAt = s.now()

	if err := s.cfg.Store.UpdateTeam(ctx, t); err != nil {
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
	if _, err := s.GetTeam(ctx, orgID, teamID); err != nil {
		return err
	}

	if err := s.cfg.Store.DeleteTeam(ctx, orgID, teamID); err != nil {
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
	return s.cfg.Store.ListTeamsByOrg(ctx, orgID)
}

// AddTeamMember enrolls a member into a team, ensuring they belong to the organization.
func (s *service) AddTeamMember(ctx context.Context, orgID, teamID, userID string) error {
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
		TeamID:    teamID,
		UserID:    userID,
		CreatedAt: s.now(),
	}

	if err := s.cfg.Store.AddTeamMember(ctx, tm); err != nil {
		if errors.Is(err, store.ErrConflict) {
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
	if _, err := s.GetTeam(ctx, orgID, teamID); err != nil {
		return err
	}

	if err := s.cfg.Store.RemoveTeamMember(ctx, teamID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrTeamMemberNotFound
		}
		return err
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
	return s.cfg.Store.ListTeamMembers(ctx, teamID)
}

// CreateInvitation generates an invitation and plaintext secret token.
func (s *service) CreateInvitation(ctx context.Context, in CreateInvitationInput) (*Invitation, string, error) {
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	in.InviterUserID = strings.TrimSpace(in.InviterUserID)

	if in.OrganizationID == "" || in.Email == "" || in.InviterUserID == "" {
		return nil, "", fmt.Errorf("%w: organization_id, email, and inviter_user_id are required", ErrInvalidInput)
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

	if err := s.cfg.Store.CreateInvitation(ctx, inv); err != nil {
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
	inv, err := s.cfg.Store.GetInvitationByID(ctx, orgID, invitationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvitationNotFound
		}
		return nil, err
	}
	return inv, nil
}

// ListInvitations lists pending invitations for an organization.
func (s *service) ListInvitations(ctx context.Context, orgID string) ([]*Invitation, error) {
	return s.cfg.Store.ListInvitationsByOrg(ctx, orgID)
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

	err := s.cfg.Store.Transaction(ctx, func(txCtx context.Context) error {
		inv, err := s.cfg.Store.GetInvitationByTokenHash(txCtx, tokenHash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
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
		if _, err := s.cfg.Store.GetMembership(txCtx, inv.OrganizationID, userID); err == nil {
			return ErrMemberAlreadyExists
		}

		inv.AcceptedAt = &now
		if err := s.cfg.Store.UpdateInvitation(txCtx, inv); err != nil {
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

		return s.cfg.Store.CreateMembership(txCtx, m)
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
	if _, err := s.GetInvitation(ctx, orgID, invitationID); err != nil {
		return err
	}

	if err := s.cfg.Store.DeleteInvitation(ctx, orgID, invitationID); err != nil {
		return err
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
