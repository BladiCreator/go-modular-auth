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
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOrganizationRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormOrganizationRepository) GetOrganizationByID(ctx context.Context, id string) (*organization.Organization, error) {
//		var org organization.Organization
//		if err := r.db.WithContext(ctx).Where("id = ?", id).First(&org).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, organization.ErrOrganizationNotFound
//			}
//			return nil, err
//		}
//		return &org, nil
//	}
type Repository interface {
	// --- Organization Operations ---

	// CreateOrganization persists a new organization tenant boundary in storage.
	//
	// Function:
	//   Called during CreateOrganization API endpoint or flow.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational organization creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - org: Organization domain entity to persist.
	//
	// Returns:
	//   - error: ErrOrganizationAlreadyExists or ErrSlugAlreadyExists on unique constraint violation.
	//
	// Example SQL:
	//   INSERT INTO organizations (id, name, slug, logo, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateOrganization(ctx context.Context, org *Organization) error

	// GetOrganizationByID retrieves an organization record by its unique ID.
	//
	// Function:
	//   Used in organization context resolution, active organization lookup, and org management.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational lookup by organization ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique organization primary key.
	//
	// Returns:
	//   - *Organization: Matching entity if found.
	//   - error: ErrOrganizationNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, name, slug, logo, metadata, created_at, updated_at FROM organizations WHERE id = $1 LIMIT 1;
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)

	// GetOrganizationBySlug retrieves an organization record by its unique URL slug.
	//
	// Function:
	//   Used during slug-based organization routing or slug availability validation.
	//
	// Storage:
	//   Database (GORM / SQL) - Query organization by slug index.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - slug: URL-friendly organization slug.
	//
	// Returns:
	//   - *Organization: Matching entity if found.
	//   - error: ErrOrganizationNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, name, slug, logo, metadata, created_at, updated_at FROM organizations WHERE slug = $1 LIMIT 1;
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)

	// UpdateOrganization updates mutable fields of an organization.
	//
	// Function:
	//   Called when updating organization settings, name, slug, logo, or metadata.
	//
	// Storage:
	//   Database (GORM / SQL) - Organization record update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - org: Modified Organization entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE organizations SET name = $1, slug = $2, logo = $3, metadata = $4, updated_at = $5 WHERE id = $6;
	UpdateOrganization(ctx context.Context, org *Organization) error

	// DeleteOrganization permanently removes an organization record and cascades related data.
	//
	// Function:
	//   Called during organization removal by an owner.
	//
	// Storage:
	//   Database (GORM / SQL) - Organization deletion with cascade.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Target organization ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM organizations WHERE id = $1;
	DeleteOrganization(ctx context.Context, id string) error

	// ListOrganizationsByUserID retrieves all organizations in which a user holds active membership.
	//
	// Function:
	//   Used during user organization switcher or listing user tenant access.
	//
	// Storage:
	//   Database (GORM / SQL) - Joined organizations and members query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - []*Organization: Slice of organizations.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT o.id, o.name, o.slug, o.logo, o.metadata, o.created_at, o.updated_at
	//   FROM organizations o JOIN organization_members m ON o.id = m.organization_id WHERE m.user_id = $1;
	ListOrganizationsByUserID(ctx context.Context, userID string) ([]*Organization, error)

	// --- Member Operations ---

	// CreateMember adds a user to an organization with an assigned role.
	//
	// Function:
	//   Called during initial organization creation (adding creator as owner) or accepting an invitation.
	//
	// Storage:
	//   Database (GORM / SQL) - Member relation insertion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - member: Member entity to persist.
	//
	// Returns:
	//   - error: ErrMemberAlreadyExists if already joined.
	//
	// Example SQL:
	//   INSERT INTO organization_members (id, organization_id, user_id, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateMember(ctx context.Context, member *Member) error

	// GetMember retrieves a membership record linking a user to an organization.
	//
	// Function:
	//   Used during permission authorization checks to verify user role in an org.
	//
	// Storage:
	//   Database (GORM / SQL) - Member record lookup by org & user ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//   - userID: User identifier.
	//
	// Returns:
	//   - *Member: Matching membership record if found.
	//   - error: ErrMemberNotFound if user is not in org.
	//
	// Example SQL:
	//   SELECT id, organization_id, user_id, role, created_at, updated_at FROM organization_members WHERE organization_id = $1 AND user_id = $2 LIMIT 1;
	GetMember(ctx context.Context, orgID, userID string) (*Member, error)

	// GetMemberByID retrieves a membership record by its primary key ID.
	//
	// Function:
	//   Used in member detail views or administrative operations.
	//
	// Storage:
	//   Database (GORM / SQL) - Member primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - memberID: Membership record primary key.
	//
	// Returns:
	//   - *Member: Matching membership record.
	//   - error: ErrMemberNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, organization_id, user_id, role, created_at, updated_at FROM organization_members WHERE id = $1 LIMIT 1;
	GetMemberByID(ctx context.Context, memberID string) (*Member, error)

	// UpdateMember updates the assigned role of an organization member.
	//
	// Function:
	//   Called when promoting or demoting member roles.
	//
	// Storage:
	//   Database (GORM / SQL) - Member role update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - member: Modified Member entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE organization_members SET role = $1, updated_at = $2 WHERE id = $3;
	UpdateMember(ctx context.Context, member *Member) error

	// DeleteMember removes a member from an organization.
	//
	// Function:
	//   Called when removing a member or when a member leaves an organization.
	//
	// Storage:
	//   Database (GORM / SQL) - Member record removal.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - userID: User ID to remove.
	//
	// Returns:
	//   - error: ErrCannotRemoveLastOwner if attempting to remove the sole remaining owner.
	//
	// Example SQL:
	//   DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2;
	DeleteMember(ctx context.Context, orgID, userID string) error

	// ListMembers retrieves a paginated list of organization members with enriched user profiles.
	//
	// Function:
	//   Used in team settings / member directory UI.
	//
	// Storage:
	//   Database (GORM / SQL) - Paginated joined member profiles query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - limit: Page size limit.
	//   - offset: Pagination offset.
	//
	// Returns:
	//   - []*Member: Slice of members.
	//   - int: Total member count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT m.id, m.organization_id, m.user_id, m.role, m.created_at, m.updated_at, u.email, u.name
	//   FROM organization_members m JOIN users u ON m.user_id = u.id WHERE m.organization_id = $1 LIMIT $2 OFFSET $3;
	ListMembers(ctx context.Context, orgID string, limit, offset int) ([]*Member, int, error)

	// CountMembersByRole returns the number of members holding a specific role in an organization.
	//
	// Function:
	//   Used to enforce minimum owner rules before demoting or removing members.
	//
	// Storage:
	//   Database (GORM / SQL) - Count members matching role.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - role: Target role string (e.g. "owner").
	//
	// Returns:
	//   - int: Member count with target role.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM organization_members WHERE organization_id = $1 AND role = $2;
	CountMembersByRole(ctx context.Context, orgID, role string) (int, error)

	// CountMembers returns the total member count in an organization.
	//
	// Function:
	//   Used to enforce organization membership quota limits.
	//
	// Storage:
	//   Database (GORM / SQL) - Total organization members count.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//
	// Returns:
	//   - int: Total count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM organization_members WHERE organization_id = $1;
	CountMembers(ctx context.Context, orgID string) (int, error)

	// --- Invitation Operations ---

	// CreateInvitation persists a new email invitation to join an organization.
	//
	// Function:
	//   Called when an admin/owner invites a user by email.
	//
	// Storage:
	//   Database (GORM / SQL) - Invitation record creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - invitation: Invitation entity to store.
	//
	// Returns:
	//   - error: ErrInvitationAlreadyExists if a pending invitation already exists for the email.
	//
	// Example SQL:
	//   INSERT INTO organization_invitations (id, organization_id, email, role, status, team_id, inviter_id, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	CreateInvitation(ctx context.Context, invitation *Invitation) error

	// GetInvitationByID retrieves an invitation record by ID.
	//
	// Function:
	//   Called when accepting or rejecting an invitation using an invitation link/token.
	//
	// Storage:
	//   Database (GORM / SQL) - Invitation record query by ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Invitation ID.
	//
	// Returns:
	//   - *Invitation: Matching record if found.
	//   - error: ErrInvitationNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, status, team_id, inviter_id, expires_at, created_at FROM organization_invitations WHERE id = $1 LIMIT 1;
	GetInvitationByID(ctx context.Context, id string) (*Invitation, error)

	// GetPendingInvitation retrieves an active pending invitation by organization ID and email.
	//
	// Function:
	//   Used to check for duplicate pending invitations before issuing a new one.
	//
	// Storage:
	//   Database (GORM / SQL) - Pending invitation lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - email: Recipient email address.
	//
	// Returns:
	//   - *Invitation: Pending invitation if found.
	//   - error: ErrInvitationNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, status, team_id, inviter_id, expires_at, created_at FROM organization_invitations WHERE organization_id = $1 AND email = $2 AND status = 'pending' LIMIT 1;
	GetPendingInvitation(ctx context.Context, orgID, email string) (*Invitation, error)

	// UpdateInvitation updates the status (e.g. accepted, revoked, expired) of an invitation.
	//
	// Function:
	//   Called during invitation state transitions.
	//
	// Storage:
	//   Database (GORM / SQL) - Invitation status update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - invitation: Modified Invitation entity.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE organization_invitations SET status = $1 WHERE id = $2;
	UpdateInvitation(ctx context.Context, invitation *Invitation) error

	// DeleteInvitation removes an invitation record from storage.
	//
	// Function:
	//   Called when cancelling or revoking an invitation.
	//
	// Storage:
	//   Database (GORM / SQL) - Invitation record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Invitation ID.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM organization_invitations WHERE id = $1;
	DeleteInvitation(ctx context.Context, id string) error

	// ListInvitationsByOrgID lists invitations for an organization, optionally filtered by status.
	//
	// Function:
	//   Used in organization settings to view pending/sent invitations.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational invitations list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - status: Optional status filter pointer.
	//
	// Returns:
	//   - []*Invitation: List of matching invitations.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, status, team_id, inviter_id, expires_at, created_at FROM organization_invitations WHERE organization_id = $1 AND status = $2;
	ListInvitationsByOrgID(ctx context.Context, orgID string, status *InvitationStatus) ([]*Invitation, error)

	// ListInvitationsByEmail lists invitations sent to a user's email across all organizations.
	//
	// Function:
	//   Used in user dashboard to display pending organization invites for the logged-in user.
	//
	// Storage:
	//   Database (GORM / SQL) - User invitations list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - email: Recipient email address.
	//   - status: Optional status filter.
	//
	// Returns:
	//   - []*Invitation: List of invitations.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, status, team_id, inviter_id, expires_at, created_at FROM organization_invitations WHERE email = $1 AND status = $2;
	ListInvitationsByEmail(ctx context.Context, email string, status *InvitationStatus) ([]*Invitation, error)

	// CountPendingInvitations returns the count of active pending invitations for an org.
	//
	// Function:
	//   Used to enforce pending invitation limits.
	//
	// Storage:
	//   Database (GORM / SQL) - Pending invitations count.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//
	// Returns:
	//   - int: Pending count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM organization_invitations WHERE organization_id = $1 AND status = 'pending';
	CountPendingInvitations(ctx context.Context, orgID string) (int, error)

	// --- Team Operations (Optional Sub-module) ---

	// CreateTeam creates a sub-team within an organization.
	//
	// Function:
	//   Called when creating a team within an organization.
	//
	// Storage:
	//   Database (GORM / SQL) - Team entity creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - team: Team entity to persist.
	//
	// Returns:
	//   - error: ErrTeamAlreadyExists if team name is taken in org.
	//
	// Example SQL:
	//   INSERT INTO organization_teams (id, organization_id, name, created_at, updated_at) VALUES ($1, $2, $3, $4, $5);
	CreateTeam(ctx context.Context, team *Team) error

	// GetTeamByID retrieves a team by ID.
	//
	// Function:
	//   Used in team management endpoints.
	//
	// Storage:
	//   Database (GORM / SQL) - Team lookup by ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Team ID.
	//
	// Returns:
	//   - *Team: Team entity if found.
	//   - error: ErrTeamNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, organization_id, name, created_at, updated_at FROM organization_teams WHERE id = $1 LIMIT 1;
	GetTeamByID(ctx context.Context, id string) (*Team, error)

	// UpdateTeam updates mutable team attributes.
	//
	// Function:
	//   Called when renaming a team.
	//
	// Storage:
	//   Database (GORM / SQL) - Team record update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - team: Modified Team entity.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE organization_teams SET name = $1, updated_at = $2 WHERE id = $3;
	UpdateTeam(ctx context.Context, team *Team) error

	// DeleteTeam removes a team and unassigns members.
	//
	// Function:
	//   Called during team deletion.
	//
	// Storage:
	//   Database (GORM / SQL) - Team deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Team ID.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM organization_teams WHERE id = $1;
	DeleteTeam(ctx context.Context, id string) error

	// ListTeamsByOrgID lists all teams belonging to an organization.
	//
	// Function:
	//   Used in team directory views.
	//
	// Storage:
	//   Database (GORM / SQL) - Teams list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//
	// Returns:
	//   - []*Team: List of teams.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, organization_id, name, created_at, updated_at FROM organization_teams WHERE organization_id = $1;
	ListTeamsByOrgID(ctx context.Context, orgID string) ([]*Team, error)

	// ListTeamsByUserID lists teams in an organization to which a user belongs.
	//
	// Function:
	//   Used to filter user team memberships.
	//
	// Storage:
	//   Database (GORM / SQL) - User teams list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - []*Team: List of teams.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT t.id, t.organization_id, t.name, t.created_at, t.updated_at
	//   FROM organization_teams t JOIN organization_team_members tm ON t.id = tm.team_id WHERE t.organization_id = $1 AND tm.user_id = $2;
	ListTeamsByUserID(ctx context.Context, orgID, userID string) ([]*Team, error)

	// CountTeams returns the count of teams in an organization.
	//
	// Function:
	//   Used to enforce team limit quotas.
	//
	// Storage:
	//   Database (GORM / SQL) - Organization teams count.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//
	// Returns:
	//   - int: Count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM organization_teams WHERE organization_id = $1;
	CountTeams(ctx context.Context, orgID string) (int, error)

	// --- Team Member Operations ---

	// AddTeamMember assigns a user to a team.
	//
	// Function:
	//   Called when adding an org member to a team.
	//
	// Storage:
	//   Database (GORM / SQL) - Team member mapping creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamMember: TeamMember entity.
	//
	// Returns:
	//   - error: ErrTeamMemberAlreadyExists if user is already in team.
	//
	// Example SQL:
	//   INSERT INTO organization_team_members (id, team_id, user_id, created_at) VALUES ($1, $2, $3, $4);
	AddTeamMember(ctx context.Context, teamMember *TeamMember) error

	// RemoveTeamMember unassigns a user from a team.
	//
	// Function:
	//   Called when removing a user from a team.
	//
	// Storage:
	//   Database (GORM / SQL) - Team member mapping deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamID: Team ID.
	//   - userID: User ID.
	//
	// Returns:
	//   - error: ErrTeamMemberNotFound if user was not in team.
	//
	// Example SQL:
	//   DELETE FROM organization_team_members WHERE team_id = $1 AND user_id = $2;
	RemoveTeamMember(ctx context.Context, teamID, userID string) error

	// GetTeamMember retrieves a team member mapping record.
	//
	// Function:
	//   Used to check team membership.
	//
	// Storage:
	//   Database (GORM / SQL) - Team member mapping lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamID: Team ID.
	//   - userID: User ID.
	//
	// Returns:
	//   - *TeamMember: Team member record.
	//   - error: ErrTeamMemberNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, team_id, user_id, created_at FROM organization_team_members WHERE team_id = $1 AND user_id = $2 LIMIT 1;
	GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error)

	// ListTeamMembers lists all member assignments for a team.
	//
	// Function:
	//   Used in team member listing.
	//
	// Storage:
	//   Database (GORM / SQL) - Team members list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamID: Team ID.
	//
	// Returns:
	//   - []*TeamMember: Slice of team members.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, team_id, user_id, created_at FROM organization_team_members WHERE team_id = $1;
	ListTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error)

	// CountTeamMembers counts members assigned to a team.
	//
	// Function:
	//   Used to check team capacity limits.
	//
	// Storage:
	//   Database (GORM / SQL) - Team members count.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamID: Team ID.
	//
	// Returns:
	//   - int: Count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM organization_team_members WHERE team_id = $1;
	CountTeamMembers(ctx context.Context, teamID string) (int, error)

	// --- Dynamic Access Control Operations ---

	// CreateRole creates a dynamic custom role within an organization.
	//
	// Function:
	//   Called when defining custom organization roles.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic role creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - role: OrganizationRole entity.
	//
	// Returns:
	//   - error: ErrRoleAlreadyExists if role name is taken.
	//
	// Example SQL:
	//   INSERT INTO organization_roles (id, organization_id, role_name, permissions, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateRole(ctx context.Context, role *OrganizationRole) error

	// GetRoleByID retrieves a custom dynamic role by ID.
	//
	// Function:
	//   Used in role permission evaluation.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic role lookup by ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Role ID.
	//
	// Returns:
	//   - *OrganizationRole: Role entity if found.
	//   - error: ErrRoleNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, organization_id, role_name, permissions, created_at, updated_at FROM organization_roles WHERE id = $1 LIMIT 1;
	GetRoleByID(ctx context.Context, id string) (*OrganizationRole, error)

	// GetRoleByName retrieves a dynamic role by name within an organization.
	//
	// Function:
	//   Used during member role permission verification.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic role lookup by name.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//   - roleName: Role identifier string.
	//
	// Returns:
	//   - *OrganizationRole: Role entity.
	//   - error: ErrRoleNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, organization_id, role_name, permissions, created_at, updated_at FROM organization_roles WHERE organization_id = $1 AND role_name = $2 LIMIT 1;
	GetRoleByName(ctx context.Context, orgID, roleName string) (*OrganizationRole, error)

	// UpdateRole updates dynamic role permissions.
	//
	// Function:
	//   Called when modifying custom role permissions.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic role permissions update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - role: Modified OrganizationRole entity.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE organization_roles SET permissions = $1, updated_at = $2 WHERE id = $3;
	UpdateRole(ctx context.Context, role *OrganizationRole) error

	// DeleteRole removes a custom dynamic role.
	//
	// Function:
	//   Called when removing custom roles.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic role deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Role ID.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM organization_roles WHERE id = $1;
	DeleteRole(ctx context.Context, id string) error

	// ListRolesByOrgID lists all custom dynamic roles defined in an organization.
	//
	// Function:
	//   Used in role management UI.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic roles list query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//
	// Returns:
	//   - []*OrganizationRole: List of roles.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT id, organization_id, role_name, permissions, created_at, updated_at FROM organization_roles WHERE organization_id = $1;
	ListRolesByOrgID(ctx context.Context, orgID string) ([]*OrganizationRole, error)

	// CountRoles counts custom dynamic roles defined in an organization.
	//
	// Function:
	//   Used to enforce dynamic role limits.
	//
	// Storage:
	//   Database (GORM / SQL) - Dynamic roles count.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization ID.
	//
	// Returns:
	//   - int: Count.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM organization_roles WHERE organization_id = $1;
	CountRoles(ctx context.Context, orgID string) (int, error)
}
