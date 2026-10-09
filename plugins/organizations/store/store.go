// Package store defines the persistence contract for the organizations multi-tenant plugin.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested record does not exist.
	ErrNotFound = errors.New("organizations store: record not found")

	// ErrConflict indicates that a unique constraint (such as slug, member, or token hash) has been violated.
	ErrConflict = errors.New("organizations store: record already exists")
)

// Role represents a member's role within an organization.
type Role string

const (
	// RoleOwner possesses full administrative authority over the organization.
	RoleOwner Role = "owner"

	// RoleAdmin can manage members, teams, invitations, and settings.
	RoleAdmin Role = "admin"

	// RoleMember is a standard collaborator with standard organizational access.
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
	// MembershipActive indicates an active and authorized member.
	MembershipActive MembershipStatus = "active"

	// MembershipSuspended indicates that member access has been temporarily revoked.
	MembershipSuspended MembershipStatus = "suspended"
)

// Organization represents an isolated multi-tenant tenant boundary.
type Organization struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Slug      string            `json:"slug"`
	OwnerID   string            `json:"owner_id"` // UserID reference
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Membership represents the association between a Core User and an Organization.
type Membership struct {
	ID             string           `json:"id"`
	OrganizationID string           `json:"organization_id"`
	UserID         string           `json:"user_id"` // UserID reference
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
	TeamID    string    `json:"team_id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Invitation represents an invitation sent to an email address to join an organization.
// The plaintext token secret is never stored; only TokenHash is persisted.
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
	if inv.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(inv.ExpiresAt)
}

// Accepted reports whether the invitation has already been redeemed.
func (inv *Invitation) Accepted() bool {
	return inv.AcceptedAt != nil
}

// Active reports whether the invitation can still be redeemed.
func (inv *Invitation) Active(now time.Time) bool {
	return !inv.Accepted() && !inv.Expired(now)
}

// Store defines the persistent storage contract required by the organizations plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOrganizationStore struct {
//		db *gorm.DB
//	}
//
//	func (s *GormOrganizationStore) GetOrganizationByID(ctx context.Context, id string) (*store.Organization, error) {
//		var org store.Organization
//		if err := s.db.WithContext(ctx).Where("id = ?", id).First(&org).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, store.ErrNotFound
//			}
//			return nil, err
//		}
//		return &org, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because `GetMembership` and `GetOrganizationByID` are invoked on **every authenticated organization-scoped request**,
// querying the relational database on every HTTP call can become a performance bottleneck.
// Decorating your database store with Redis or an in-memory Cache-Aside wrapper is strongly recommended:
//
//	type CachedOrganizationStore struct {
//		dbStore store.Store
//		redis   *redis.Client
//		ttl     time.Duration
//	}
//
//	func (s *CachedOrganizationStore) GetMembership(ctx context.Context, orgID, userID string) (*store.Membership, error) {
//		cacheKey := "gomodularauth:organizations:membership:" + orgID + ":" + userID
//		val, err := s.redis.Get(ctx, cacheKey).Bytes()
//		if err == nil {
//			var mem store.Membership
//			if json.Unmarshal(val, &mem) == nil {
//				return &mem, nil // Fast Cache Hit ($O(1)$)
//			}
//		}
//		mem, err := s.dbStore.GetMembership(ctx, orgID, userID)
//		if err != nil {
//			return nil, err
//		}
//		bytes, _ := json.Marshal(mem)
//		s.redis.Set(ctx, cacheKey, bytes, s.ttl)
//		return mem, nil
//	}
type Store interface {
	// Transaction runs fn atomically within a storage transaction.
	//
	// Function:
	//   Executes multi-entity operations (such as creating an organization and owner membership) atomically.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - fn: Transaction body function.
	//
	// Returns:
	//   - error: Nil on successful commit, or error causing rollback.
	//
	// Example SQL:
	//   BEGIN; ... COMMIT;
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error

	// CreateOrganization persists a new organization record.
	//
	// Function:
	//   Creates a new organization tenant boundary.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - org: Organization entity to create.
	//
	// Returns:
	//   - error: ErrConflict if slug or ID already exists, or infrastructure error.
	//
	// Example SQL:
	//   INSERT INTO auth_organizations (id, name, slug, owner_id, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateOrganization(ctx context.Context, org *Organization) error

	// GetOrganizationByID retrieves an organization record by its primary ID.
	//
	// Function:
	//   Looks up organization details during request authorization or tenant resolution.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency lookup per organization-scoped API request.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique organization identifier.
	//
	// Returns:
	//   - *store.Organization: Organization entity if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, name, slug, owner_id, metadata, created_at, updated_at FROM auth_organizations WHERE id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "gomodularauth:organizations:org:" + id).Bytes()
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)

	// GetOrganizationBySlug retrieves an organization by its unique URL slug.
	//
	// Function:
	//   Resolves tenant by subdomain or URL route parameter.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Subdomain or URL path tenant routing.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - slug: Unique organization slug.
	//
	// Returns:
	//   - *store.Organization: Organization entity if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, name, slug, owner_id, metadata, created_at, updated_at FROM auth_organizations WHERE slug = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "gomodularauth:organizations:slug:" + slug).Bytes()
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)

	// UpdateOrganization updates mutable fields of an existing organization.
	//
	// Function:
	//   Updates organization name, metadata, or owner ID.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - org: Organization entity with updated values.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_organizations SET name = $1, owner_id = $2, metadata = $3, updated_at = $4 WHERE id = $5;
	UpdateOrganization(ctx context.Context, org *Organization) error

	// DeleteOrganization deletes an organization and associated resources.
	//
	// Function:
	//   Removes an entire tenant boundary.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique organization identifier.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_organizations WHERE id = $1;
	DeleteOrganization(ctx context.Context, id string) error

	// ListOrganizationsByUser returns all organizations where userID is an active member.
	//
	// Function:
	//   Queries organizations accessible to a user for tenant selection menus.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Core user ID.
	//
	// Returns:
	//   - []*store.Organization: Slice of organization entities.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT o.id, o.name, o.slug, o.owner_id, o.metadata, o.created_at, o.updated_at FROM auth_organizations o INNER JOIN auth_organization_memberships m ON o.id = m.organization_id WHERE m.user_id = $1 AND m.status = 'active';
	ListOrganizationsByUser(ctx context.Context, userID string) ([]*Organization, error)

	// CreateMembership persists a new membership record.
	//
	// Function:
	//   Associates a Core user with an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - m: Membership record to create.
	//
	// Returns:
	//   - error: ErrConflict if (organization_id, user_id) already exists.
	//
	// Example SQL:
	//   INSERT INTO auth_organization_memberships (id, organization_id, user_id, role, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateMembership(ctx context.Context, m *Membership) error

	// GetMembership retrieves a member record by organization ID and user ID.
	//
	// Function:
	//   Validates member role and status during organization authorization checks.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency check on every authorized request.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Target organization identifier.
	//   - userID: Authenticated user identifier.
	//
	// Returns:
	//   - *store.Membership: Membership entity if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, user_id, role, status, created_at, updated_at FROM auth_organization_memberships WHERE organization_id = $1 AND user_id = $2 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "gomodularauth:organizations:membership:" + orgID + ":" + userID).Bytes()
	GetMembership(ctx context.Context, orgID, userID string) (*Membership, error)

	// UpdateMembership updates mutable fields of an existing membership.
	//
	// Function:
	//   Updates member role or status (e.g. active, suspended).
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - m: Updated membership entity.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_organization_memberships SET role = $1, status = $2, updated_at = $3 WHERE organization_id = $4 AND user_id = $5;
	UpdateMembership(ctx context.Context, m *Membership) error

	// DeleteMembership permanently deletes a membership association.
	//
	// Function:
	//   Removes a user from an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//   - userID: User identifier.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_organization_memberships WHERE organization_id = $1 AND user_id = $2;
	DeleteMembership(ctx context.Context, orgID, userID string) error

	// ListMembershipsByOrg returns all memberships for an organization.
	//
	// Function:
	//   Retrieves member roster for administrative views.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Target organization identifier.
	//
	// Returns:
	//   - []*store.Membership: Slice of member entities.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, user_id, role, status, created_at, updated_at FROM auth_organization_memberships WHERE organization_id = $1 ORDER BY created_at ASC;
	ListMembershipsByOrg(ctx context.Context, orgID string) ([]*Membership, error)

	// CreateTeam persists a new team record.
	//
	// Function:
	//   Creates a new department or team inside an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - t: Team entity to create.
	//
	// Returns:
	//   - error: ErrConflict if team slug already exists in organization.
	//
	// Example SQL:
	//   INSERT INTO auth_organization_teams (id, organization_id, name, slug, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateTeam(ctx context.Context, t *Team) error

	// GetTeamByID retrieves a team by its ID scoped to the organization.
	//
	// Function:
	//   Fetches team details ensuring tenant isolation.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization boundary identifier.
	//   - teamID: Unique team identifier.
	//
	// Returns:
	//   - *store.Team: Team entity if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, name, slug, description, created_at, updated_at FROM auth_organization_teams WHERE organization_id = $1 AND id = $2 LIMIT 1;
	GetTeamByID(ctx context.Context, orgID, teamID string) (*Team, error)

	// GetTeamBySlug retrieves a team by its slug scoped to the organization.
	//
	// Function:
	//   Fetches team details using slug identifier within an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//   - slug: Team slug.
	//
	// Returns:
	//   - *store.Team: Team entity if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, name, slug, description, created_at, updated_at FROM auth_organization_teams WHERE organization_id = $1 AND slug = $2 LIMIT 1;
	GetTeamBySlug(ctx context.Context, orgID, slug string) (*Team, error)

	// UpdateTeam updates mutable fields of an existing team.
	//
	// Function:
	//   Modifies team name or description.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - t: Updated team entity.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_organization_teams SET name = $1, description = $2, updated_at = $3 WHERE organization_id = $4 AND id = $5;
	UpdateTeam(ctx context.Context, t *Team) error

	// DeleteTeam permanently deletes a team and its member associations.
	//
	// Function:
	//   Removes a team from an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//   - teamID: Team identifier.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_organization_teams WHERE organization_id = $1 AND id = $2;
	DeleteTeam(ctx context.Context, orgID, teamID string) error

	// ListTeamsByOrg returns all teams belonging to an organization.
	//
	// Function:
	//   Retrieves teams roster for an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//
	// Returns:
	//   - []*store.Team: Slice of team entities.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, name, slug, description, created_at, updated_at FROM auth_organization_teams WHERE organization_id = $1 ORDER BY created_at ASC;
	ListTeamsByOrg(ctx context.Context, orgID string) ([]*Team, error)

	// AddTeamMember enrolls a member into a team.
	//
	// Function:
	//   Associates a user with a team.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tm: Team membership entity.
	//
	// Returns:
	//   - error: ErrConflict if user is already enrolled in the team.
	//
	// Example SQL:
	//   INSERT INTO auth_organization_team_members (team_id, user_id, created_at) VALUES ($1, $2, $3);
	AddTeamMember(ctx context.Context, tm *TeamMembership) error

	// RemoveTeamMember removes a user from a team.
	//
	// Function:
	//   Disenrolls a member from a team.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamID: Target team identifier.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_organization_team_members WHERE team_id = $1 AND user_id = $2;
	RemoveTeamMember(ctx context.Context, teamID, userID string) error

	// ListTeamMembers returns all user IDs enrolled in a team.
	//
	// Function:
	//   Retrieves user roster of a team.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - teamID: Team identifier.
	//
	// Returns:
	//   - []string: Slice of user IDs.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT user_id FROM auth_organization_team_members WHERE team_id = $1;
	ListTeamMembers(ctx context.Context, teamID string) ([]string, error)

	// CreateInvitation persists a new invitation record.
	//
	// Function:
	//   Stores an invitation for an email to join an organization.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - inv: Invitation entity.
	//
	// Returns:
	//   - error: ErrConflict if token hash already exists.
	//
	// Example SQL:
	//   INSERT INTO auth_organization_invitations (id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	CreateInvitation(ctx context.Context, inv *Invitation) error

	// GetInvitationByID retrieves an invitation by ID within an organization.
	//
	// Function:
	//   Retrieves invitation details for inspection or revocation.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization boundary identifier.
	//   - id: Unique invitation identifier.
	//
	// Returns:
	//   - *store.Invitation: Invitation entity if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at FROM auth_organization_invitations WHERE organization_id = $1 AND id = $2 LIMIT 1;
	GetInvitationByID(ctx context.Context, orgID, id string) (*Invitation, error)

	// GetInvitationByTokenHash retrieves an invitation by the SHA-256 hash of its redemption token.
	//
	// Function:
	//   Redeems an invitation during user acceptance workflow.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tokenHash: SHA-256 hex string of the invitation token.
	//
	// Returns:
	//   - *store.Invitation: Matching invitation entity.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at FROM auth_organization_invitations WHERE token_hash = $1 LIMIT 1;
	GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*Invitation, error)

	// UpdateInvitation updates an invitation (e.g. marking AcceptedAt).
	//
	// Function:
	//   Updates invitation status during acceptance or expiry.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - inv: Updated invitation entity.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_organization_invitations SET accepted_at = $1 WHERE id = $2;
	UpdateInvitation(ctx context.Context, inv *Invitation) error

	// DeleteInvitation deletes an invitation.
	//
	// Function:
	//   Revokes an invitation prior to acceptance.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//   - id: Invitation identifier.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_organization_invitations WHERE organization_id = $1 AND id = $2;
	DeleteInvitation(ctx context.Context, orgID, id string) error

	// ListInvitationsByOrg lists all pending invitations for an organization.
	//
	// Function:
	//   Queries active invitations for organization management.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - orgID: Organization identifier.
	//
	// Returns:
	//   - []*store.Invitation: Slice of invitation entities.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at FROM auth_organization_invitations WHERE organization_id = $1 ORDER BY created_at DESC;
	ListInvitationsByOrg(ctx context.Context, orgID string) ([]*Invitation, error)
}
