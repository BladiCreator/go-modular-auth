package organization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the Organization plugin ("organization").
const PluginID = "organization"

var nonAlphaNumRegex = regexp.MustCompile(`[^a-z0-9]+`)

// Plugin implements multi-tenancy, member, team, and invitation management capabilities.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new Organization plugin instance configured with a repository and functional options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique identifier for the Organization plugin ("organization").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration settings of the Organization plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// Repository returns the underlying storage repository instance.
func (p *Plugin) Repository() Repository {
	return p.repo
}

// Helper: generateRandomID generates a cryptographically secure random hexadecimal ID string.
func generateRandomID(prefix string, length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// Helper: slugify converts a string into a normalized URL-friendly slug.
func slugify(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = nonAlphaNumRegex.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return generateRandomID("org-", 4)
	}
	return s
}

// Helper: publishEvent safely publishes an event to the EventBus if initialized.
func (p *Plugin) publishEvent(topic string, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(topic, payload)
	}
}

// Organization Operations

// CreateOrganization creates a new tenant organization, registers the creator as its initial owner member,
// optionally spins up a default team, and marks the organization as active for the user.
func (p *Plugin) CreateOrganization(ctx context.Context, params CreateOrganizationParams) (*CreateOrganizationResult, error) {
	if params.UserID == "" || strings.TrimSpace(params.Name) == "" {
		return nil, ErrInvalidParameter
	}

	// 1. Check authorization if callback provided
	if p.config.AllowUserToCreateOrganization != nil {
		allowed, err := p.config.AllowUserToCreateOrganization(ctx, params.UserID)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Check organization creation limit
	if p.config.OrganizationLimit != nil {
		maxOrgs, err := p.config.OrganizationLimit(ctx, params.UserID)
		if err != nil {
			return nil, err
		}
		if maxOrgs > 0 {
			userOrgs, err := p.repo.ListOrganizationsByUserID(ctx, params.UserID)
			if err != nil {
				return nil, err
			}
			if len(userOrgs) >= maxOrgs {
				return nil, ErrOrganizationLimitReached
			}
		}
	}

	// 3. Resolve and validate Slug
	slug := params.Slug
	if strings.TrimSpace(slug) == "" {
		slug = slugify(params.Name)
	} else {
		slug = slugify(slug)
	}

	existingOrg, err := p.repo.GetOrganizationBySlug(ctx, slug)
	if err == nil && existingOrg != nil {
		return nil, ErrSlugAlreadyExists
	}

	// 4. Emit Before Event
	p.publishEvent(EventOrgCreateBefore, &OrgCreateBeforeEventPayload{
		UserID:   params.UserID,
		Name:     params.Name,
		Slug:     slug,
		Logo:     params.Logo,
		Metadata: params.Metadata,
		ExtraContainer: params.ExtraContainer,
	})

	// 5. Create Organization Entity
	org := &Organization{
		ID:        generateRandomID("org_", 12),
		Name:      strings.TrimSpace(params.Name),
		Slug:      slug,
		Logo:      params.Logo,
		Metadata:  params.Metadata,
		CreatedAt: time.Now(),
	}

	if err := p.repo.CreateOrganization(ctx, org); err != nil {
		return nil, err
	}

	// 6. Create Owner Member Entity
	creatorRole := p.config.CreatorRole
	if creatorRole == "" {
		creatorRole = RoleOwner
	}

	member := &Member{
		ID:             generateRandomID("mem_", 12),
		OrganizationID: org.ID,
		UserID:         params.UserID,
		Role:           creatorRole,
		CreatedAt:      time.Now(),
	}

	if err := p.repo.CreateMember(ctx, member); err != nil {
		return nil, err
	}

	// 7. Optional Default Team Creation
	if p.config.TeamsEnabled && p.config.DefaultTeamEnabled {
		defaultTeam := &Team{
			ID:             generateRandomID("team_", 12),
			OrganizationID: org.ID,
			Name:           "General",
			CreatedAt:      time.Now(),
		}
		if err := p.repo.CreateTeam(ctx, defaultTeam); err == nil {
			_ = p.repo.AddTeamMember(ctx, &TeamMember{
				ID:        generateRandomID("tm_", 12),
				TeamID:    defaultTeam.ID,
				UserID:    params.UserID,
				CreatedAt: time.Now(),
			})
		}
	}

	// 8. Set Active Organization in Context
	if p.ctx != nil {
		p.ctx.Set(ActiveOrgContextKey(params.UserID), org.ID)
	}

	// 9. Emit After Event
	p.publishEvent(EventOrgCreateAfter, &OrgCreateAfterEventPayload{
		Organization: org,
		Member:       member,
		ExtraContainer: params.ExtraContainer,
	})

	return &CreateOrganizationResult{
		Organization: org,
		Member:       member,
	}, nil
}

// GetOrganization retrieves an organization by its unique identifier.
func (p *Plugin) GetOrganization(ctx context.Context, params GetOrganizationParams) (*GetOrganizationResult, error) {
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	org, err := p.repo.GetOrganizationByID(ctx, params.OrganizationID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationResult{Organization: org}, nil
}

// GetOrganizationBySlug retrieves an organization by its URL-friendly slug.
func (p *Plugin) GetOrganizationBySlug(ctx context.Context, params GetOrganizationBySlugParams) (*GetOrganizationBySlugResult, error) {
	if params.Slug == "" {
		return nil, ErrInvalidParameter
	}

	org, err := p.repo.GetOrganizationBySlug(ctx, params.Slug)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationBySlugResult{Organization: org}, nil
}

// GetFullOrganization retrieves the complete organization details along with members, active invitations, and teams.
func (p *Plugin) GetFullOrganization(ctx context.Context, params GetFullOrganizationParams) (*GetFullOrganizationResult, error) {
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	org, err := p.repo.GetOrganizationByID(ctx, params.OrganizationID)
	if err != nil {
		return nil, err
	}

	members, _, err := p.repo.ListMembers(ctx, params.OrganizationID, 0, 0)
	if err != nil {
		return nil, err
	}

	invitations, err := p.repo.ListInvitationsByOrgID(ctx, params.OrganizationID, nil)
	if err != nil {
		return nil, err
	}

	var teams []*Team
	if p.config.TeamsEnabled {
		teams, err = p.repo.ListTeamsByOrgID(ctx, params.OrganizationID)
		if err != nil {
			return nil, err
		}
	}

	return &GetFullOrganizationResult{
		Organization: org,
		Members:      members,
		Invitations:  invitations,
		Teams:        teams,
	}, nil
}

// UpdateOrganization modifies properties of an existing organization after verifying user update permissions.
func (p *Plugin) UpdateOrganization(ctx context.Context, params UpdateOrganizationParams) (*UpdateOrganizationResult, error) {
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	// 1. RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, member.Role, Permissions{
			ResourceOrganization: {ActionUpdate},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Fetch existing organization
	org, err := p.repo.GetOrganizationByID(ctx, params.OrganizationID)
	if err != nil {
		return nil, err
	}

	// 3. Check Slug Uniqueness if slug is being updated
	if params.Slug != nil && *params.Slug != "" && *params.Slug != org.Slug {
		normalizedSlug := slugify(*params.Slug)
		existing, err := p.repo.GetOrganizationBySlug(ctx, normalizedSlug)
		if err == nil && existing != nil && existing.ID != org.ID {
			return nil, ErrSlugAlreadyExists
		}
		org.Slug = normalizedSlug
	}

	if params.Name != nil && strings.TrimSpace(*params.Name) != "" {
		org.Name = strings.TrimSpace(*params.Name)
	}
	if params.Logo != nil {
		org.Logo = *params.Logo
	}
	if params.Metadata != nil {
		org.Metadata = params.Metadata
	}
	now := time.Now()
	org.UpdatedAt = &now

	// 4. Emit Before Event
	p.publishEvent(EventOrgUpdateBefore, &OrgUpdateBeforeEventPayload{
		OrganizationID: org.ID,
		Name:           params.Name,
		Slug:           params.Slug,
		Logo:           params.Logo,
		Metadata:       params.Metadata,
		ExtraContainer: params.ExtraContainer,
	})

	// 5. Persist Update
	if err := p.repo.UpdateOrganization(ctx, org); err != nil {
		return nil, err
	}

	// 6. Emit After Event
	p.publishEvent(EventOrgUpdateAfter, &OrgUpdateAfterEventPayload{
		Organization:   org,
		ExtraContainer: params.ExtraContainer,
	})

	return &UpdateOrganizationResult{Organization: org}, nil
}

// DeleteOrganization removes an organization after verifying user delete permissions.
func (p *Plugin) DeleteOrganization(ctx context.Context, params DeleteOrganizationParams) (*DeleteOrganizationResult, error) {
	if params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	// 1. RBAC Permission Check if UserID is provided
	if params.UserID != "" {
		member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
		if err != nil {
			return nil, ErrPermissionDenied
		}
		allowed, err := p.CheckPermission(ctx, params.OrganizationID, member.Role, Permissions{
			ResourceOrganization: {ActionDelete},
		})
		if err != nil || !allowed {
			return nil, ErrPermissionDenied
		}
	}

	// 2. Emit Before Event
	p.publishEvent(EventOrgDeleteBefore, &OrgDeleteBeforeEventPayload{
		OrganizationID: params.OrganizationID,
		ExtraContainer: params.ExtraContainer,
	})

	// 3. Persist Deletion
	if err := p.repo.DeleteOrganization(ctx, params.OrganizationID); err != nil {
		return nil, fmt.Errorf("organization: failed to delete organization: %w", err)
	}

	// 4. Emit After Event
	p.publishEvent(EventOrgDeleteAfter, &OrgDeleteAfterEventPayload{
		OrganizationID: params.OrganizationID,
		ExtraContainer: params.ExtraContainer,
	})

	return &DeleteOrganizationResult{Success: true}, nil
}

// ListOrganizations returns all organizations where the specified user is a member.
func (p *Plugin) ListOrganizations(ctx context.Context, params ListOrganizationsParams) (*ListOrganizationsResult, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	orgs, err := p.repo.ListOrganizationsByUserID(ctx, params.UserID)
	if err != nil {
		return nil, err
	}

	return &ListOrganizationsResult{Organizations: orgs}, nil
}

// CheckSlug checks whether an organization slug is available for registration.
func (p *Plugin) CheckSlug(ctx context.Context, params CheckSlugParams) (*CheckSlugResult, error) {
	if strings.TrimSpace(params.Slug) == "" {
		return nil, ErrInvalidParameter
	}

	normalized := slugify(params.Slug)
	_, err := p.repo.GetOrganizationBySlug(ctx, normalized)
	if err != nil {
		return &CheckSlugResult{Available: true}, nil
	}

	return &CheckSlugResult{Available: false}, nil
}

// SetActiveOrganization stores the active organization context for a user in the shared context store.
func (p *Plugin) SetActiveOrganization(ctx context.Context, params SetActiveOrganizationParams) (*SetActiveOrganizationResult, error) {
	if params.UserID == "" || params.OrganizationID == "" {
		return nil, ErrInvalidParameter
	}

	org, err := p.repo.GetOrganizationByID(ctx, params.OrganizationID)
	if err != nil {
		return nil, err
	}

	member, err := p.repo.GetMember(ctx, params.OrganizationID, params.UserID)
	if err != nil {
		return nil, ErrMemberNotFound
	}

	p.publishEvent(EventOrgSetActiveBefore, &OrgSetActiveBeforeEventPayload{
		UserID:         params.UserID,
		OrganizationID: params.OrganizationID,
		ExtraContainer: params.ExtraContainer,
	})

	if p.ctx != nil {
		p.ctx.Set(ActiveOrgContextKey(params.UserID), params.OrganizationID)
	}

	p.publishEvent(EventOrgSetActiveAfter, &OrgSetActiveAfterEventPayload{
		UserID:         params.UserID,
		OrganizationID: params.OrganizationID,
		Organization:   org,
		Member:         member,
		ExtraContainer: params.ExtraContainer,
	})

	return &SetActiveOrganizationResult{
		Organization: org,
		Member:       member,
	}, nil
}

// GetActiveOrganization retrieves the currently active organization and membership for a user.
func (p *Plugin) GetActiveOrganization(ctx context.Context, params GetActiveOrganizationParams) (*GetActiveOrganizationResult, error) {
	if params.UserID == "" {
		return nil, ErrInvalidParameter
	}

	var activeOrgID string
	if p.ctx != nil {
		if val, ok := p.ctx.Get(ActiveOrgContextKey(params.UserID)); ok {
			if idStr, ok := val.(string); ok {
				activeOrgID = idStr
			}
		}
	}

	if activeOrgID == "" {
		// Fallback to user's first organization if available
		userOrgs, err := p.repo.ListOrganizationsByUserID(ctx, params.UserID)
		if err != nil || len(userOrgs) == 0 {
			return nil, ErrOrganizationNotFound
		}
		activeOrgID = userOrgs[0].ID
		if p.ctx != nil {
			p.ctx.Set(ActiveOrgContextKey(params.UserID), activeOrgID)
		}
	}

	org, err := p.repo.GetOrganizationByID(ctx, activeOrgID)
	if err != nil {
		return nil, err
	}

	member, err := p.repo.GetMember(ctx, activeOrgID, params.UserID)
	if err != nil {
		return nil, ErrMemberNotFound
	}

	return &GetActiveOrganizationResult{
		Organization: org,
		Member:       member,
	}, nil
}
