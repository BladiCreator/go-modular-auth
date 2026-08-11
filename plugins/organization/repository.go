package organization

import (
	"context"
	"errors"
	"time"
)

// Domain Models

// Organization represents a tenant boundary containing members, teams, invitations, and custom roles.
type Organization struct {
	// ID is the unique string identifier for the organization.
	ID string `json:"id"`

	// Name is the display name of the organization.
	Name string `json:"name"`

	// Slug is the unique URL-friendly slug identifier for the organization.
	Slug string `json:"slug"`

	// Logo is an optional URL pointing to the organization's logo or avatar.
	Logo string `json:"logo,omitempty"`

	// Metadata holds arbitrary key-value properties associated with the organization.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreatedAt marks the timestamp when the organization was created.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt marks the timestamp when the organization was last modified.
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// UserInfo represents enriched user identity information attached to member records.
type UserInfo struct {
	// ID is the unique user identifier.
	ID string `json:"id"`

	// Email is the user's primary email address.
	Email string `json:"email"`

	// Name is the user's display name.
	Name string `json:"name"`

	// Image is an optional avatar or profile image URL.
	Image string `json:"image,omitempty"`
}

// Member represents the membership relation connecting a user to an organization with an assigned role.
type Member struct {
	// ID is the unique identifier for the membership record.
	ID string `json:"id"`

	// OrganizationID identifies the parent organization.
	OrganizationID string `json:"organizationId"`

	// UserID identifies the associated user.
	UserID string `json:"userId"`

	// Role is the assigned role name (e.g. "owner", "admin", "member", or comma-separated compound roles).
	Role string `json:"role"`

	// CreatedAt marks when the user joined the organization.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt marks when the membership record was last updated.
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`

	// User contains enriched user profile information when populated.
	User *UserInfo `json:"user,omitempty"`
}

// Invitation represents an email invitation dispatched to invite a user into an organization.
type Invitation struct {
	// ID is the unique invitation identifier.
	ID string `json:"id"`

	// OrganizationID identifies the organization to which the user is invited.
	OrganizationID string `json:"organizationId"`

	// Email is the recipient email address.
	Email string `json:"email"`

	// Role is the role to be assigned upon accepting the invitation.
	Role string `json:"role"`

	// Status indicates the current lifecycle status of the invitation.
	Status InvitationStatus `json:"status"`

	// TeamID optionally associates an initial team assignment upon accepting.
	TeamID *string `json:"teamId,omitempty"`

	// InviterID identifies the user who dispatched the invitation.
	InviterID string `json:"inviterId"`

	// ExpiresAt specifies the exact timestamp when the invitation expires.
	ExpiresAt time.Time `json:"expiresAt"`

	// CreatedAt marks when the invitation was issued.
	CreatedAt time.Time `json:"createdAt"`
}

// Team represents a sub-unit or squad within an organization.
type Team struct {
	// ID is the unique team identifier.
	ID string `json:"id"`

	// OrganizationID identifies the parent organization.
	OrganizationID string `json:"organizationId"`

	// Name is the display name of the team.
	Name string `json:"name"`

	// CreatedAt marks when the team was created.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt marks when the team was last updated.
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// TeamMember represents the membership relation connecting a user to a specific team.
type TeamMember struct {
	// ID is the unique identifier for the team membership record.
	ID string `json:"id"`

	// TeamID identifies the team.
	TeamID string `json:"teamId"`

	// UserID identifies the member user.
	UserID string `json:"userId"`

	// CreatedAt marks when the user joined the team.
	CreatedAt time.Time `json:"createdAt"`
}

// OrganizationRole represents a dynamic, organization-scoped custom role and its permission matrix.
type OrganizationRole struct {
	// ID is the unique role identifier.
	ID string `json:"id"`

	// OrganizationID identifies the parent organization owning the role.
	OrganizationID string `json:"organizationId"`

	// Role is the unique role name within the organization.
	Role string `json:"role"`

	// Permissions maps resource names to lists of granted actions (e.g. "member": ["create", "update"]).
	Permissions map[string][]string `json:"permissions"`

	// CreatedAt marks when the role was created.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt marks when the role was last updated.
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// Sentinel Error Definitions

var (
	// ErrOrganizationNotFound is returned when an organization matching the specified criteria does not exist.
	ErrOrganizationNotFound = errors.New("organization not found")

	// ErrOrganizationAlreadyExists is returned when attempting to create an organization that already exists.
	ErrOrganizationAlreadyExists = errors.New("organization already exists")

	// ErrSlugAlreadyExists is returned when the requested slug is already taken by another organization.
	ErrSlugAlreadyExists = errors.New("organization slug already exists")

	// ErrMemberNotFound is returned when a user is not a member of the specified organization.
	ErrMemberNotFound = errors.New("member not found in organization")

	// ErrMemberAlreadyExists is returned when attempting to add a user who is already a member of the organization.
	ErrMemberAlreadyExists = errors.New("member already exists in organization")

	// ErrCannotRemoveLastOwner is returned when attempting to remove or demote the last remaining owner in an organization.
	ErrCannotRemoveLastOwner = errors.New("cannot remove or demote the last owner of the organization")

	// ErrCannotLeaveAsLastOwner is returned when the last owner attempts to leave the organization without transferring ownership.
	ErrCannotLeaveAsLastOwner = errors.New("cannot leave organization as the last owner without transferring ownership")

	// ErrInvitationNotFound is returned when an invitation cannot be found by ID or email.
	ErrInvitationNotFound = errors.New("invitation not found")

	// ErrInvitationExpired is returned when attempting to accept or process an expired invitation.
	ErrInvitationExpired = errors.New("invitation has expired")

	// ErrInvitationAlreadyExists is returned when a pending invitation already exists for the email in the organization.
	ErrInvitationAlreadyExists = errors.New("a pending invitation already exists for this email in the organization")

	// ErrInvalidInvitationStatus is returned when an action requires an invitation in 'pending' status but found otherwise.
	ErrInvalidInvitationStatus = errors.New("invitation status is invalid for this operation")

	// ErrTeamNotFound is returned when a team does not exist in the organization.
	ErrTeamNotFound = errors.New("team not found")

	// ErrTeamAlreadyExists is returned when a team name already exists within the organization.
	ErrTeamAlreadyExists = errors.New("team already exists in organization")

	// ErrTeamMemberNotFound is returned when a user is not a member of the specified team.
	ErrTeamMemberNotFound = errors.New("team member not found")

	// ErrTeamMemberAlreadyExists is returned when a user is already assigned to the specified team.
	ErrTeamMemberAlreadyExists = errors.New("user is already a member of the team")

	// ErrCannotRemoveAllTeams is returned when attempting to delete the last team while AllowRemovingAllTeams is false.
	ErrCannotRemoveAllTeams = errors.New("cannot remove all teams from organization")

	// ErrRoleNotFound is returned when a dynamic role cannot be found in the organization.
	ErrRoleNotFound = errors.New("dynamic role not found")

	// ErrRoleAlreadyExists is returned when a role with the given name already exists in the organization.
	ErrRoleAlreadyExists = errors.New("role name already exists in organization")

	// ErrPermissionDenied is returned when the current user's role lacks sufficient permissions to execute an action.
	ErrPermissionDenied = errors.New("permission denied")

	// ErrOrganizationLimitReached is returned when a user exceeds the allowed limit of created organizations.
	ErrOrganizationLimitReached = errors.New("maximum number of organizations reached")

	// ErrMembershipLimitReached is returned when an organization exceeds its maximum allowed members.
	ErrMembershipLimitReached = errors.New("maximum number of organization members reached")

	// ErrInvitationLimitReached is returned when an organization exceeds its maximum allowed pending invitations.
	ErrInvitationLimitReached = errors.New("maximum number of pending invitations reached")

	// ErrTeamsLimitReached is returned when an organization exceeds its maximum allowed teams.
	ErrTeamsLimitReached = errors.New("maximum number of teams reached")

	// ErrTeamMembersLimitReached is returned when a team exceeds its maximum allowed members.
	ErrTeamMembersLimitReached = errors.New("maximum number of team members reached")

	// ErrRolesLimitReached is returned when an organization exceeds its maximum allowed dynamic roles.
	ErrRolesLimitReached = errors.New("maximum number of dynamic roles reached")

	// ErrTeamsNotEnabled is returned when attempting team operations while the teams sub-module is disabled.
	ErrTeamsNotEnabled = errors.New("teams module is not enabled")

	// ErrDynamicACNotEnabled is returned when attempting dynamic role operations while dynamic AC is disabled.
	ErrDynamicACNotEnabled = errors.New("dynamic access control is not enabled")

	// ErrEmailNotVerified is returned when email verification is required before sending or accepting invitations.
	ErrEmailNotVerified = errors.New("email verification is required for invitations")

	// ErrInvalidParameter is returned when an invalid argument or parameter is supplied to an operation.
	ErrInvalidParameter = errors.New("invalid parameter provided")
)

// Repository defines the storage contract for persisting and querying organization-related domain entities.
type Repository interface {
	// Organization Operations
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizationsByUserID(ctx context.Context, userID string) ([]*Organization, error)

	// Member Operations
	CreateMember(ctx context.Context, member *Member) error
	GetMember(ctx context.Context, orgID, userID string) (*Member, error)
	GetMemberByID(ctx context.Context, memberID string) (*Member, error)
	UpdateMember(ctx context.Context, member *Member) error
	DeleteMember(ctx context.Context, orgID, userID string) error
	ListMembers(ctx context.Context, orgID string, limit, offset int) ([]*Member, int, error)
	CountMembersByRole(ctx context.Context, orgID, role string) (int, error)
	CountMembers(ctx context.Context, orgID string) (int, error)

	// Invitation Operations
	CreateInvitation(ctx context.Context, invitation *Invitation) error
	GetInvitationByID(ctx context.Context, id string) (*Invitation, error)
	GetPendingInvitation(ctx context.Context, orgID, email string) (*Invitation, error)
	UpdateInvitation(ctx context.Context, invitation *Invitation) error
	DeleteInvitation(ctx context.Context, id string) error
	ListInvitationsByOrgID(ctx context.Context, orgID string, status *InvitationStatus) ([]*Invitation, error)
	ListInvitationsByEmail(ctx context.Context, email string, status *InvitationStatus) ([]*Invitation, error)
	CountPendingInvitations(ctx context.Context, orgID string) (int, error)

	// Team Operations (Optional Sub-module)
	CreateTeam(ctx context.Context, team *Team) error
	GetTeamByID(ctx context.Context, id string) (*Team, error)
	UpdateTeam(ctx context.Context, team *Team) error
	DeleteTeam(ctx context.Context, id string) error
	ListTeamsByOrgID(ctx context.Context, orgID string) ([]*Team, error)
	ListTeamsByUserID(ctx context.Context, orgID, userID string) ([]*Team, error)
	CountTeams(ctx context.Context, orgID string) (int, error)

	// Team Member Operations
	AddTeamMember(ctx context.Context, teamMember *TeamMember) error
	RemoveTeamMember(ctx context.Context, teamID, userID string) error
	GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error)
	ListTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error)
	CountTeamMembers(ctx context.Context, teamID string) (int, error)

	// Dynamic Access Control Operations
	CreateRole(ctx context.Context, role *OrganizationRole) error
	GetRoleByID(ctx context.Context, id string) (*OrganizationRole, error)
	GetRoleByName(ctx context.Context, orgID, roleName string) (*OrganizationRole, error)
	UpdateRole(ctx context.Context, role *OrganizationRole) error
	DeleteRole(ctx context.Context, id string) error
	ListRolesByOrgID(ctx context.Context, orgID string) ([]*OrganizationRole, error)
	CountRoles(ctx context.Context, orgID string) (int, error)
}
