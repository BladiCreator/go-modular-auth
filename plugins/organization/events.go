// Package organization defines event names and typed event payloads published by the Organization plugin on the global EventBus.
package organization

// Event Name Constants
const (
	// Organization Events
	EventOrgCreateBefore    = "org:create:before"
	EventOrgCreateAfter     = "org:create:after"
	EventOrgUpdateBefore    = "org:update:before"
	EventOrgUpdateAfter     = "org:update:after"
	EventOrgDeleteBefore    = "org:delete:before"
	EventOrgDeleteAfter     = "org:delete:after"
	EventOrgSetActiveBefore = "org:set_active:before"
	EventOrgSetActiveAfter  = "org:set_active:after"

	// Member Events
	EventMemberAddBefore        = "org:member:add:before"
	EventMemberAddAfter         = "org:member:add:after"
	EventMemberRemoveBefore     = "org:member:remove:before"
	EventMemberRemoveAfter      = "org:member:remove:after"
	EventMemberRoleUpdateBefore = "org:member:role_update:before"
	EventMemberRoleUpdateAfter  = "org:member:role_update:after"
	EventMemberLeaveBefore      = "org:member:leave:before"
	EventMemberLeaveAfter       = "org:member:leave:after"

	// Invitation Events
	EventInvitationCreateBefore = "org:invitation:create:before"
	EventInvitationCreateAfter  = "org:invitation:create:after"
	EventInvitationAcceptBefore = "org:invitation:accept:before"
	EventInvitationAcceptAfter  = "org:invitation:accept:after"
	EventInvitationRejectBefore = "org:invitation:reject:before"
	EventInvitationRejectAfter  = "org:invitation:reject:after"
	EventInvitationCancelBefore = "org:invitation:cancel:before"
	EventInvitationCancelAfter  = "org:invitation:cancel:after"

	// Team Events
	EventTeamCreateBefore       = "org:team:create:before"
	EventTeamCreateAfter        = "org:team:create:after"
	EventTeamUpdateBefore       = "org:team:update:before"
	EventTeamUpdateAfter        = "org:team:update:after"
	EventTeamDeleteBefore       = "org:team:delete:before"
	EventTeamDeleteAfter        = "org:team:delete:after"
	EventTeamMemberAddBefore    = "org:team_member:add:before"
	EventTeamMemberAddAfter     = "org:team_member:add:after"
	EventTeamMemberRemoveBefore = "org:team_member:remove:before"
	EventTeamMemberRemoveAfter  = "org:team_member:remove:after"
	EventTeamSetActiveBefore    = "org:team:set_active:before"
	EventTeamSetActiveAfter     = "org:team:set_active:after"

	// Dynamic Role Events
	EventRoleCreateBefore = "org:role:create:before"
	EventRoleCreateAfter  = "org:role:create:after"
	EventRoleUpdateBefore = "org:role:update:before"
	EventRoleUpdateAfter  = "org:role:update:after"
	EventRoleDeleteBefore = "org:role:delete:before"
	EventRoleDeleteAfter  = "org:role:delete:after"
)

// Typed Event Payloads

// Organization Payloads

type OrgCreateBeforeEventPayload struct {
	UserID   string
	Name     string
	Slug     string
	Logo     string
	Metadata map[string]any
	Extra    map[string]any
}

type OrgCreateAfterEventPayload struct {
	Organization *Organization
	Member       *Member
	Extra        map[string]any
}

type OrgUpdateBeforeEventPayload struct {
	OrganizationID string
	Name           *string
	Slug           *string
	Logo           *string
	Metadata       map[string]any
	Extra          map[string]any
}

type OrgUpdateAfterEventPayload struct {
	Organization *Organization
	Extra        map[string]any
}

type OrgDeleteBeforeEventPayload struct {
	OrganizationID string
	Extra          map[string]any
}

type OrgDeleteAfterEventPayload struct {
	OrganizationID string
	Extra          map[string]any
}

type OrgSetActiveBeforeEventPayload struct {
	UserID         string
	OrganizationID string
	Extra          map[string]any
}

type OrgSetActiveAfterEventPayload struct {
	UserID         string
	OrganizationID string
	Organization   *Organization
	Member         *Member
	Extra          map[string]any
}

// Member Payloads

type MemberAddBeforeEventPayload struct {
	OrganizationID string
	UserID         string
	Role           string
	Extra          map[string]any
}

type MemberAddAfterEventPayload struct {
	Member *Member
	Extra  map[string]any
}

type MemberRemoveBeforeEventPayload struct {
	OrganizationID string
	UserID         string
	Extra          map[string]any
}

type MemberRemoveAfterEventPayload struct {
	OrganizationID string
	UserID         string
	Extra          map[string]any
}

type MemberRoleUpdateBeforeEventPayload struct {
	OrganizationID string
	UserID         string
	NewRole        string
	Extra          map[string]any
}

type MemberRoleUpdateAfterEventPayload struct {
	Member *Member
	Extra  map[string]any
}

type MemberLeaveBeforeEventPayload struct {
	OrganizationID string
	UserID         string
	Extra          map[string]any
}

type MemberLeaveAfterEventPayload struct {
	OrganizationID string
	UserID         string
	Extra          map[string]any
}

// Invitation Payloads

type InvitationCreateBeforeEventPayload struct {
	OrganizationID string
	InviterID      string
	Email          string
	Role           string
	TeamID         *string
	Extra          map[string]any
}

type InvitationCreateAfterEventPayload struct {
	Invitation *Invitation
	Extra      map[string]any
}

type InvitationAcceptBeforeEventPayload struct {
	InvitationID string
	UserID       string
	Extra        map[string]any
}

type InvitationAcceptAfterEventPayload struct {
	Invitation   *Invitation
	Member       *Member
	Organization *Organization
	Extra        map[string]any
}

type InvitationRejectBeforeEventPayload struct {
	InvitationID string
	UserID       string
	Extra        map[string]any
}

type InvitationRejectAfterEventPayload struct {
	Invitation *Invitation
	Extra      map[string]any
}

type InvitationCancelBeforeEventPayload struct {
	InvitationID string
	UserID       string
	Extra        map[string]any
}

type InvitationCancelAfterEventPayload struct {
	Invitation *Invitation
	Extra      map[string]any
}

// Team Payloads

type TeamCreateBeforeEventPayload struct {
	OrganizationID string
	Name           string
	Extra          map[string]any
}

type TeamCreateAfterEventPayload struct {
	Team  *Team
	Extra map[string]any
}

type TeamUpdateBeforeEventPayload struct {
	TeamID string
	Name   string
	Extra  map[string]any
}

type TeamUpdateAfterEventPayload struct {
	Team  *Team
	Extra map[string]any
}

type TeamDeleteBeforeEventPayload struct {
	TeamID string
	Extra  map[string]any
}

type TeamDeleteAfterEventPayload struct {
	TeamID string
	Extra  map[string]any
}

type TeamMemberAddBeforeEventPayload struct {
	TeamID string
	UserID string
	Extra  map[string]any
}

type TeamMemberAddAfterEventPayload struct {
	TeamMember *TeamMember
	Extra      map[string]any
}

type TeamMemberRemoveBeforeEventPayload struct {
	TeamID string
	UserID string
	Extra  map[string]any
}

type TeamMemberRemoveAfterEventPayload struct {
	TeamID string
	UserID string
	Extra  map[string]any
}

type TeamSetActiveBeforeEventPayload struct {
	UserID string
	TeamID string
	Extra  map[string]any
}

type TeamSetActiveAfterEventPayload struct {
	UserID string
	TeamID string
	Team   *Team
	Extra  map[string]any
}

// Dynamic Role Payloads

type RoleCreateBeforeEventPayload struct {
	OrganizationID string
	Role           string
	Permissions    map[string][]string
	Extra          map[string]any
}

type RoleCreateAfterEventPayload struct {
	Role  *OrganizationRole
	Extra map[string]any
}

type RoleUpdateBeforeEventPayload struct {
	RoleID      string
	Role        *string
	Permissions map[string][]string
	Extra       map[string]any
}

type RoleUpdateAfterEventPayload struct {
	Role  *OrganizationRole
	Extra map[string]any
}

type RoleDeleteBeforeEventPayload struct {
	RoleID string
	Extra  map[string]any
}

type RoleDeleteAfterEventPayload struct {
	RoleID string
	Extra  map[string]any
}
