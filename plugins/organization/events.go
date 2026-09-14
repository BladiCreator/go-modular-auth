// Package organization defines event names and typed event payloads published by the Organization plugin on the shared Hooks dispatcher.
package organization

import (
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
	}

	OrgCreateAfterEventPayload struct {
		Organization *Organization
		Member       *Member
	}

	OrgUpdateBeforeEventPayload struct {
		OrganizationID string
		Name           *string
		Slug           *string
		Logo           *string
		Metadata       map[string]any
	}

	OrgUpdateAfterEventPayload struct {
		Organization *Organization
	}

	OrgDeleteBeforeEventPayload struct {
		OrganizationID string
	}

	OrgDeleteAfterEventPayload struct {
		OrganizationID string
	}

	OrgSetActiveBeforeEventPayload struct {
		UserID         string
		OrganizationID string
	}

	OrgSetActiveAfterEventPayload struct {
		UserID         string
		OrganizationID string
		Organization   *Organization
		Member         *Member
	}

	// Member Payloads

	MemberAddBeforeEventPayload struct {
		OrganizationID string
		UserID         string
		Role           string
	}

	MemberAddAfterEventPayload struct {
		Member *Member
	}

	MemberRemoveBeforeEventPayload struct {
		OrganizationID string
		UserID         string
	}

	MemberRemoveAfterEventPayload struct {
		OrganizationID string
		UserID         string
	}

	MemberRoleUpdateBeforeEventPayload struct {
		OrganizationID string
		UserID         string
		NewRole        string
	}

	MemberRoleUpdateAfterEventPayload struct {
		Member *Member
	}

	MemberLeaveBeforeEventPayload struct {
		OrganizationID string
		UserID         string
	}

	MemberLeaveAfterEventPayload struct {
		OrganizationID string
		UserID         string
	}

	// Invitation Payloads

	InvitationCreateBeforeEventPayload struct {
		OrganizationID string
		InviterID      string
		Email          string
		Role           string
		TeamID         *string
	}

	InvitationCreateAfterEventPayload struct {
		Invitation *Invitation
	}

	InvitationAcceptBeforeEventPayload struct {
		InvitationID string
		UserID       string
	}

	InvitationAcceptAfterEventPayload struct {
		Invitation   *Invitation
		Member       *Member
		Organization *Organization
	}

	InvitationRejectBeforeEventPayload struct {
		InvitationID string
		UserID       string
	}

	InvitationRejectAfterEventPayload struct {
		Invitation *Invitation
	}

	InvitationCancelBeforeEventPayload struct {
		InvitationID string
		UserID       string
	}

	InvitationCancelAfterEventPayload struct {
		Invitation *Invitation
	}

	// Team Payloads

	TeamCreateBeforeEventPayload struct {
		OrganizationID string
		Name           string
	}

	TeamCreateAfterEventPayload struct {
		Team *Team
	}

	TeamUpdateBeforeEventPayload struct {
		TeamID string
		Name   string
	}

	TeamUpdateAfterEventPayload struct {
		Team *Team
	}

	TeamDeleteBeforeEventPayload struct {
		TeamID string
	}

	TeamDeleteAfterEventPayload struct {
		TeamID string
	}

	TeamMemberAddBeforeEventPayload struct {
		TeamID string
		UserID string
	}

	TeamMemberAddAfterEventPayload struct {
		TeamMember *TeamMember
	}

	TeamMemberRemoveBeforeEventPayload struct {
		TeamID string
		UserID string
	}

	TeamMemberRemoveAfterEventPayload struct {
		TeamID string
		UserID string
	}

	TeamSetActiveBeforeEventPayload struct {
		UserID string
		TeamID string
	}

	TeamSetActiveAfterEventPayload struct {
		UserID string
		TeamID string
		Team   *Team
	}

	// Dynamic Role Payloads

	RoleCreateBeforeEventPayload struct {
		OrganizationID string
		Role           string
		Permissions    map[string][]string
	}

	RoleCreateAfterEventPayload struct {
		Role *OrganizationRole
	}

	RoleUpdateBeforeEventPayload struct {
		RoleID      string
		Role        *string
		Permissions map[string][]string
	}

	RoleUpdateAfterEventPayload struct {
		Role *OrganizationRole
	}

	RoleDeleteBeforeEventPayload struct {
		RoleID string
	}

	RoleDeleteAfterEventPayload struct {
		RoleID string
	}
)
