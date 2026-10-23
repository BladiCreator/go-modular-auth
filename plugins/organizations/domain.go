package organizations

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// Role represents a member's role within an organization.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Level returns a numerical hierarchy level for the standard roles.
func (r Role) Level() int {
	switch r {
	case RoleOwner:
		return 30
	case RoleAdmin:
		return 20
	case RoleMember:
		return 10
	default:
		return 0
	}
}

// AtLeast reports whether role r satisfies or exceeds the required target role.
func (r Role) AtLeast(target Role) bool {
	return r.Level() >= target.Level()
}

// MembershipStatus indicates the lifecycle state of an organization membership.
type MembershipStatus string

const (
	MembershipActive    MembershipStatus = "active"
	MembershipSuspended MembershipStatus = "suspended"
)

// OrganizationRecord represents an isolated multi-tenant tenant boundary.
type OrganizationRecord struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Slug      string            `json:"slug"`
	OwnerID   string            `json:"owner_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Membership represents the association between a Core User and an Organization.
type Membership struct {
	ID             string           `json:"id"`
	OrganizationID string           `json:"organization_id"`
	UserID         string           `json:"user_id"`
	Role           Role             `json:"role"`
	Status         MembershipStatus `json:"status"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

// Active reports whether the membership is active.
func (m *Membership) Active() bool {
	return m != nil && m.Status == MembershipActive
}

// Team represents a logical group of members within an organization.
type Team struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Description    string    `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TeamMembership represents a user's enrollment within a team.
type TeamMembership struct {
	ID        string    `json:"id"`
	TeamID    string    `json:"team_id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Invitation represents an invitation sent to an email address to join an organization.
type Invitation struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Email          string     `json:"email"`
	Role           Role       `json:"role"`
	InviterUserID  string     `json:"inviter_user_id"`
	TokenHash      string     `json:"token_hash"`
	ExpiresAt      time.Time  `json:"expires_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Expired reports whether the invitation has expired relative to the given timestamp.
func (inv *Invitation) Expired(now time.Time) bool {
	if inv == nil || inv.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(inv.ExpiresAt)
}

// Accepted reports whether the invitation has already been redeemed.
func (inv *Invitation) Accepted() bool {
	return inv != nil && inv.AcceptedAt != nil
}

// ScopedPrincipal binds an authenticated Core Principal with an Organization scope.
type ScopedPrincipal struct {
	Principal      auth.Principal
	OrganizationID string
	Membership     *Membership
}

// WithOrganizationContext returns a new context containing the target organization ID.
func WithOrganizationContext(ctx context.Context, orgID string) context.Context {
	return auth.WithOrganization(ctx, orgID)
}

// OrganizationFromContext retrieves the organization ID bound to ctx, if present.
func OrganizationFromContext(ctx context.Context) (string, bool) {
	return auth.OrganizationFrom(ctx)
}

const (
	ModelOrganizations           = "organizations"
	ModelOrganizationMemberships = "organization_memberships"
	ModelOrganizationTeams       = "organization_teams"
	ModelOrganizationTeamMembers = "organization_team_members"
	ModelOrganizationInvitations = "organization_invitations"
)

// RegisterSchema registers all organizations-related models into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	// 1. Organizations
	orgModel := schema.NewModel(ModelOrganizations, ModelOrganizations, "id")
	_ = orgModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = orgModel.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = orgModel.AddField(schema.Field{Name: "slug", Type: schema.TypeString, Required: true, Unique: true})
	_ = orgModel.AddField(schema.Field{Name: "owner_id", Type: schema.TypeString, Required: true})
	_ = orgModel.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = orgModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = orgModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	orgModel.Indexes = []schema.Index{
		{Name: "idx_organizations_slug", Fields: []string{"slug"}, Unique: true},
		{Name: "idx_organizations_owner_id", Fields: []string{"owner_id"}},
	}
	if err := s.AddModel(orgModel); err != nil {
		return err
	}

	// 2. Organization Memberships
	memModel := schema.NewModel(ModelOrganizationMemberships, ModelOrganizationMemberships, "id")
	_ = memModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = memModel.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString, Required: true})
	_ = memModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = memModel.AddField(schema.Field{Name: "role", Type: schema.TypeString, Required: true})
	_ = memModel.AddField(schema.Field{Name: "status", Type: schema.TypeString, Required: true})
	_ = memModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = memModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	memModel.Indexes = []schema.Index{
		{Name: "idx_org_memberships_user", Fields: []string{"user_id", "status"}},
		{Name: "idx_org_memberships_org_role", Fields: []string{"organization_id", "role"}},
		{Name: "uq_org_memberships", Fields: []string{"organization_id", "user_id"}, Unique: true},
	}
	if err := s.AddModel(memModel); err != nil {
		return err
	}

	// 3. Teams
	teamModel := schema.NewModel(ModelOrganizationTeams, ModelOrganizationTeams, "id")
	_ = teamModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = teamModel.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString, Required: true})
	_ = teamModel.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = teamModel.AddField(schema.Field{Name: "slug", Type: schema.TypeString, Required: true})
	_ = teamModel.AddField(schema.Field{Name: "description", Type: schema.TypeString})
	_ = teamModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = teamModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	teamModel.Indexes = []schema.Index{
		{Name: "idx_org_teams_org_id", Fields: []string{"organization_id"}},
		{Name: "uq_org_teams_slug", Fields: []string{"organization_id", "slug"}, Unique: true},
	}
	if err := s.AddModel(teamModel); err != nil {
		return err
	}

	// 4. Team Members
	tmModel := schema.NewModel(ModelOrganizationTeamMembers, ModelOrganizationTeamMembers, "id")
	_ = tmModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = tmModel.AddField(schema.Field{Name: "team_id", Type: schema.TypeString, Required: true})
	_ = tmModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = tmModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	tmModel.Indexes = []schema.Index{
		{Name: "idx_org_team_members_user", Fields: []string{"user_id"}},
		{Name: "uq_org_team_members", Fields: []string{"team_id", "user_id"}, Unique: true},
	}
	if err := s.AddModel(tmModel); err != nil {
		return err
	}

	// 5. Invitations
	invModel := schema.NewModel(ModelOrganizationInvitations, ModelOrganizationInvitations, "id")
	_ = invModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = invModel.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString, Required: true})
	_ = invModel.AddField(schema.Field{Name: "email", Type: schema.TypeString, Required: true})
	_ = invModel.AddField(schema.Field{Name: "role", Type: schema.TypeString, Required: true})
	_ = invModel.AddField(schema.Field{Name: "inviter_user_id", Type: schema.TypeString, Required: true})
	_ = invModel.AddField(schema.Field{Name: "token_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = invModel.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = invModel.AddField(schema.Field{Name: "accepted_at", Type: schema.TypeTime})
	_ = invModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	invModel.Indexes = []schema.Index{
		{Name: "idx_org_invitations_token_hash", Fields: []string{"token_hash"}, Unique: true},
		{Name: "idx_org_invitations_org_email", Fields: []string{"organization_id", "email"}},
	}
	return s.AddModel(invModel)
}
