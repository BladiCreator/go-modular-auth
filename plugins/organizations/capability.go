package organizations

import (
	"context"
	"time"
)

// CreateOrganizationInput contains parameters for creating a new organization.
type CreateOrganizationInput struct {
	Name     string            `json:"name"`
	Slug     string            `json:"slug"`
	OwnerID  string            `json:"owner_id"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// UpdateOrganizationInput contains parameters for updating an organization.
type UpdateOrganizationInput struct {
	Name     *string           `json:"name,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AddMemberInput contains parameters for adding a member to an organization.
type AddMemberInput struct {
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	Role           Role   `json:"role"`
}

// CreateTeamInput contains parameters for creating a new team.
type CreateTeamInput struct {
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Description    string `json:"description,omitempty"`
}

// UpdateTeamInput contains parameters for updating a team.
type UpdateTeamInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// CreateInvitationInput contains parameters for inviting a user by email.
type CreateInvitationInput struct {
	OrganizationID string        `json:"organization_id"`
	Email          string        `json:"email"`
	Role           Role          `json:"role"`
	InviterUserID  string        `json:"inviter_user_id"`
	TTL            time.Duration `json:"ttl,omitempty"`
}

// Organization is the strongly typed capability provided by the organizations module.
// Applications access it via auth.Get[plugins.Organization](a) or auth.Get[organizations.Organization](a).
type Organization interface {
	// --- Organization Lifecycle ---

	// CreateOrganization atomically creates a new Organization and adds the owner as the initial active member with RoleOwner.
	CreateOrganization(ctx context.Context, in CreateOrganizationInput) (*OrganizationRecord, error)

	// GetOrganization retrieves an organization by its unique ID.
	GetOrganization(ctx context.Context, orgID string) (*OrganizationRecord, error)

	// GetOrganizationBySlug retrieves an organization by its unique URL slug.
	GetOrganizationBySlug(ctx context.Context, slug string) (*OrganizationRecord, error)

	// UpdateOrganization modifies an existing organization's name or metadata.
	UpdateOrganization(ctx context.Context, orgID string, in UpdateOrganizationInput) (*OrganizationRecord, error)

	// DeleteOrganization deletes an organization, cascading to members, teams, and invitations.
	DeleteOrganization(ctx context.Context, orgID string) error

	// ListUserOrganizations retrieves all organizations where the specified user is an active member.
	ListUserOrganizations(ctx context.Context, userID string) ([]*OrganizationRecord, error)

	// TransferOwnership assigns the organization's ownership to another existing member.
	TransferOwnership(ctx context.Context, orgID, newOwnerUserID string) error

	// --- Membership Management ---

	// AddMember associates a Core User with the organization with a specific role.
	AddMember(ctx context.Context, in AddMemberInput) (*Membership, error)

	// GetMember retrieves a membership record for a user in an organization.
	GetMember(ctx context.Context, orgID, userID string) (*Membership, error)

	// UpdateMemberRole updates the role assigned to a member.
	UpdateMemberRole(ctx context.Context, orgID, userID string, role Role) (*Membership, error)

	// UpdateMemberStatus updates the membership status (e.g. active, suspended).
	UpdateMemberStatus(ctx context.Context, orgID, userID string, status MembershipStatus) (*Membership, error)

	// RemoveMember removes a user from an organization. Cannot remove the owner.
	RemoveMember(ctx context.Context, orgID, userID string) error

	// ListMembers retrieves all members of an organization.
	ListMembers(ctx context.Context, orgID string) ([]*Membership, error)

	// --- Team Management ---

	// CreateTeam creates a new team within an organization.
	CreateTeam(ctx context.Context, in CreateTeamInput) (*Team, error)

	// GetTeam retrieves a team by ID within the target organization.
	GetTeam(ctx context.Context, orgID, teamID string) (*Team, error)

	// UpdateTeam updates team details within an organization.
	UpdateTeam(ctx context.Context, orgID, teamID string, in UpdateTeamInput) (*Team, error)

	// DeleteTeam removes a team and its member associations.
	DeleteTeam(ctx context.Context, orgID, teamID string) error

	// ListTeams retrieves all teams belonging to an organization.
	ListTeams(ctx context.Context, orgID string) ([]*Team, error)

	// AddTeamMember enrolls an organization member into a team.
	AddTeamMember(ctx context.Context, orgID, teamID, userID string) error

	// RemoveTeamMember removes a user from a team.
	RemoveTeamMember(ctx context.Context, orgID, teamID, userID string) error

	// ListTeamMembers retrieves all user IDs belonging to a team.
	ListTeamMembers(ctx context.Context, orgID, teamID string) ([]string, error)

	// --- Invitations ---

	// CreateInvitation creates an invitation for an email address and returns the invitation and plaintext redemption token.
	CreateInvitation(ctx context.Context, in CreateInvitationInput) (*Invitation, string, error)

	// GetInvitation retrieves an invitation by ID within an organization.
	GetInvitation(ctx context.Context, orgID, invitationID string) (*Invitation, error)

	// ListInvitations lists all pending invitations for an organization.
	ListInvitations(ctx context.Context, orgID string) ([]*Invitation, error)

	// AcceptInvitation redeems an invitation token for a user, adding them as a member.
	AcceptInvitation(ctx context.Context, rawToken, userID string) (*Membership, error)

	// RevokeInvitation revokes an invitation before it is accepted.
	RevokeInvitation(ctx context.Context, orgID, invitationID string) error

	// --- Scoped Authorization ---

	// Authorize checks whether the context's authenticated Core Principal has active membership with at least minRole in orgID.
	Authorize(ctx context.Context, orgID string, minRole Role) (*Membership, error)
}

// Capability is an alias for Organization to support standard capability discovery conventions.
type Capability = Organization

// Organizations is an alias for Organization to support plural capability naming conventions.
type Organizations = Organization
