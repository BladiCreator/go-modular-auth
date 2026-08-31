// Package organization provides multi-tenancy, role-based access control (RBAC), team structures,
// and invitation management capabilities for the go-modular-auth ecosystem.
package organization

// Standard predefined role names within an organization.
const (
	// RoleOwner represents the highest administrative role in an organization with full control.
	RoleOwner = "owner"

	// RoleAdmin represents an administrative role with elevated management privileges.
	RoleAdmin = "admin"

	// RoleMember represents a standard member role with default read permissions.
	RoleMember = "member"
)

// Standard RBAC resource identifiers for access control statements.
const (
	// ResourceOrganization targets organization-level entities and properties.
	ResourceOrganization = "organization"

	// ResourceMember targets organization membership entities.
	ResourceMember = "member"

	// ResourceInvitation targets member invitations.
	ResourceInvitation = "invitation"

	// ResourceTeam targets organizational team entities.
	ResourceTeam = "team"

	// ResourceAccessControl targets dynamic role and permission configurations.
	ResourceAccessControl = "ac"
)

// Standard RBAC action identifiers for access control statements.
const (
	// ActionCreate represents permission to create new resources.
	ActionCreate = "create"

	// ActionRead represents permission to view or inspect resources.
	ActionRead = "read"

	// ActionUpdate represents permission to modify existing resources.
	ActionUpdate = "update"

	// ActionDelete represents permission to remove resources.
	ActionDelete = "delete"

	// ActionCancel represents permission to cancel invitations or operations.
	ActionCancel = "cancel"
)



// Standard Extra metadata keys that can be set or consumed in organization operations and events.
const (
	// ExtraKeyOrgID stores the organization identifier in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyOrgID = "org_id"

	// ExtraKeyOrgSlug stores the organization URL-friendly slug in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyOrgSlug = "org_slug"

	// ExtraKeyOrgName stores the organization display name in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyOrgName = "org_name"

	// ExtraKeyMemberRole stores the role assigned to a member in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyMemberRole = "member_role"

	// ExtraKeyTeamID stores the team identifier in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyTeamID = "team_id"

	// ExtraKeyInviterID stores the user ID of the inviter in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyInviterID = "inviter_id"

	// ExtraKeyInvitationID stores the invitation identifier in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyInvitationID = "invitation_id"

	// ExtraKeyUserID stores the associated user identifier in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyUserID = "user_id"

	// ExtraKeyEmail stores the targeted email address in dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyEmail = "email"
)

// Shared plugin context key prefixes used for active tenant context in plugin.Context.
const (
	// ContextKeyActiveOrgPrefix is the key prefix used when tracking a user's active organization in plugin.Context.
	ContextKeyActiveOrgPrefix = "org:active:"

	// ContextKeyActiveTeamPrefix is the key prefix used when tracking a user's active team in plugin.Context.
	ContextKeyActiveTeamPrefix = "org:team:active:"
)

// ActiveOrgContextKey formats the context store key used to track a user's active organization.
func ActiveOrgContextKey(userID string) string {
	return ContextKeyActiveOrgPrefix + userID
}

// ActiveTeamContextKey formats the context store key used to track a user's active team.
func ActiveTeamContextKey(userID string) string {
	return ContextKeyActiveTeamPrefix + userID
}
