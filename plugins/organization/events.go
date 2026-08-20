// Package organization defines event names and typed event payloads published by the Organization plugin on the global EventBus.
package organization

import (
	"github.com/BladiCreator/go-modular-auth/plugin"
)

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

type (
	OrgCreateBeforeEventPayload struct {
		UserID   string
		Name     string
		Slug     string
		Logo     string
		Metadata map[string]any
		plugin.ExtraContainer
	}

	OrgCreateAfterEventPayload struct {
		Organization *Organization
		Member       *Member
		plugin.ExtraContainer
	}

	OrgUpdateBeforeEventPayload struct {
		OrganizationID string
		Name           *string
		Slug           *string
		Logo           *string
		Metadata       map[string]any
		plugin.ExtraContainer
	}

	OrgUpdateAfterEventPayload struct {
		Organization *Organization
		plugin.ExtraContainer
	}

	OrgDeleteBeforeEventPayload struct {
		OrganizationID string
		plugin.ExtraContainer
	}

	OrgDeleteAfterEventPayload struct {
		OrganizationID string
		plugin.ExtraContainer
	}

	OrgSetActiveBeforeEventPayload struct {
		UserID         string
		OrganizationID string
		plugin.ExtraContainer
	}

	OrgSetActiveAfterEventPayload struct {
		UserID         string
		OrganizationID string
		Organization   *Organization
		Member         *Member
		plugin.ExtraContainer
	}

	// Member Payloads

	MemberAddBeforeEventPayload struct {
		OrganizationID string
		UserID         string
		Role           string
		plugin.ExtraContainer
	}

	MemberAddAfterEventPayload struct {
		Member *Member
		plugin.ExtraContainer
	}

	MemberRemoveBeforeEventPayload struct {
		OrganizationID string
		UserID         string
		plugin.ExtraContainer
	}

	MemberRemoveAfterEventPayload struct {
		OrganizationID string
		UserID         string
		plugin.ExtraContainer
	}

	MemberRoleUpdateBeforeEventPayload struct {
		OrganizationID string
		UserID         string
		NewRole        string
		plugin.ExtraContainer
	}

	MemberRoleUpdateAfterEventPayload struct {
		Member *Member
		plugin.ExtraContainer
	}

	MemberLeaveBeforeEventPayload struct {
		OrganizationID string
		UserID         string
		plugin.ExtraContainer
	}

	MemberLeaveAfterEventPayload struct {
		OrganizationID string
		UserID         string
		plugin.ExtraContainer
	}

	// Invitation Payloads

	InvitationCreateBeforeEventPayload struct {
		OrganizationID string
		InviterID      string
		Email          string
		Role           string
		TeamID         *string
		plugin.ExtraContainer
	}

	InvitationCreateAfterEventPayload struct {
		Invitation *Invitation
		plugin.ExtraContainer
	}

	InvitationAcceptBeforeEventPayload struct {
		InvitationID string
		UserID       string
		plugin.ExtraContainer
	}

	InvitationAcceptAfterEventPayload struct {
		Invitation   *Invitation
		Member       *Member
		Organization *Organization
		plugin.ExtraContainer
	}

	InvitationRejectBeforeEventPayload struct {
		InvitationID string
		UserID       string
		plugin.ExtraContainer
	}

	InvitationRejectAfterEventPayload struct {
		Invitation *Invitation
		plugin.ExtraContainer
	}

	InvitationCancelBeforeEventPayload struct {
		InvitationID string
		UserID       string
		plugin.ExtraContainer
	}

	InvitationCancelAfterEventPayload struct {
		Invitation *Invitation
		plugin.ExtraContainer
	}

	// Team Payloads

	TeamCreateBeforeEventPayload struct {
		OrganizationID string
		Name           string
		plugin.ExtraContainer
	}

	TeamCreateAfterEventPayload struct {
		Team *Team
		plugin.ExtraContainer
	}

	TeamUpdateBeforeEventPayload struct {
		TeamID string
		Name   string
		plugin.ExtraContainer
	}

	TeamUpdateAfterEventPayload struct {
		Team *Team
		plugin.ExtraContainer
	}

	TeamDeleteBeforeEventPayload struct {
		TeamID string
		plugin.ExtraContainer
	}

	TeamDeleteAfterEventPayload struct {
		TeamID string
		plugin.ExtraContainer
	}

	TeamMemberAddBeforeEventPayload struct {
		TeamID string
		UserID string
		plugin.ExtraContainer
	}

	TeamMemberAddAfterEventPayload struct {
		TeamMember *TeamMember
		plugin.ExtraContainer
	}

	TeamMemberRemoveBeforeEventPayload struct {
		TeamID string
		UserID string
		plugin.ExtraContainer
	}

	TeamMemberRemoveAfterEventPayload struct {
		TeamID string
		UserID string
		plugin.ExtraContainer
	}

	TeamSetActiveBeforeEventPayload struct {
		UserID string
		TeamID string
		plugin.ExtraContainer
	}

	TeamSetActiveAfterEventPayload struct {
		UserID string
		TeamID string
		Team   *Team
		plugin.ExtraContainer
	}

	// Dynamic Role Payloads

	RoleCreateBeforeEventPayload struct {
		OrganizationID string
		Role           string
		Permissions    map[string][]string
		plugin.ExtraContainer
	}

	RoleCreateAfterEventPayload struct {
		Role *OrganizationRole
		plugin.ExtraContainer
	}

	RoleUpdateBeforeEventPayload struct {
		RoleID      string
		Role        *string
		Permissions map[string][]string
		plugin.ExtraContainer
	}

	RoleUpdateAfterEventPayload struct {
		Role *OrganizationRole
		plugin.ExtraContainer
	}

	RoleDeleteBeforeEventPayload struct {
		RoleID string
		plugin.ExtraContainer
	}

	RoleDeleteAfterEventPayload struct {
		RoleID string
		plugin.ExtraContainer
	}
)
