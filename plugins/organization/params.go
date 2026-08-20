package organization

import (
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Parameter and Result Structs

// Organization Parameter & Result Structs

type (
	CreateOrganizationParams struct {
		UserID   string         `json:"user_id"`
		Name     string         `json:"name"`
		Slug     string         `json:"slug,omitempty"`
		Logo     string         `json:"logo,omitempty"`
		Metadata map[string]any `json:"metadata,omitempty"`
		plugin.ExtraContainer
	}

	CreateOrganizationResult struct {
		Organization *Organization `json:"organization"`
		Member       *Member       `json:"member"`
	}

	GetOrganizationParams struct {
		OrganizationID string `json:"organization_id"`
		plugin.ExtraContainer
	}

	GetOrganizationResult struct {
		Organization *Organization `json:"organization"`
	}

	GetOrganizationBySlugParams struct {
		Slug string `json:"slug"`
		plugin.ExtraContainer
	}

	GetOrganizationBySlugResult struct {
		Organization *Organization `json:"organization"`
	}

	GetFullOrganizationParams struct {
		OrganizationID string `json:"organization_id"`
		plugin.ExtraContainer
	}

	GetFullOrganizationResult struct {
		Organization *Organization `json:"organization"`
		Members      []*Member     `json:"members"`
		Invitations  []*Invitation `json:"invitations"`
		Teams        []*Team       `json:"teams,omitempty"`
	}

	UpdateOrganizationParams struct {
		OrganizationID string         `json:"organization_id"`
		UserID         string         `json:"user_id,omitempty"`
		Name           *string        `json:"name,omitempty"`
		Slug           *string        `json:"slug,omitempty"`
		Logo           *string        `json:"logo,omitempty"`
		Metadata       map[string]any `json:"metadata,omitempty"`
		plugin.ExtraContainer
	}

	UpdateOrganizationResult struct {
		Organization *Organization `json:"organization"`
	}

	DeleteOrganizationParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id,omitempty"`
		plugin.ExtraContainer
	}

	DeleteOrganizationResult struct {
		Success bool `json:"success"`
	}

	ListOrganizationsParams struct {
		UserID string `json:"user_id"`
		plugin.ExtraContainer
	}

	ListOrganizationsResult struct {
		Organizations []*Organization `json:"organizations"`
	}

	CheckSlugParams struct {
		Slug string `json:"slug"`
		plugin.ExtraContainer
	}

	CheckSlugResult struct {
		Available bool `json:"available"`
	}

	SetActiveOrganizationParams struct {
		UserID         string `json:"user_id"`
		OrganizationID string `json:"organization_id"`
		plugin.ExtraContainer
	}

	SetActiveOrganizationResult struct {
		Organization *Organization `json:"organization"`
		Member       *Member       `json:"member"`
	}

	GetActiveOrganizationParams struct {
		UserID string `json:"user_id"`
		plugin.ExtraContainer
	}

	GetActiveOrganizationResult struct {
		Organization *Organization `json:"organization"`
		Member       *Member       `json:"member"`
	}

	// Member Parameter & Result Structs

	AddMemberParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id"`
		Role           string `json:"role"`
		InvokingUserID string `json:"invoking_user_id,omitempty"`
		plugin.ExtraContainer
	}

	AddMemberResult struct {
		Member *Member `json:"member"`
	}

	GetMemberParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id"`
		plugin.ExtraContainer
	}

	GetMemberResult struct {
		Member *Member `json:"member"`
	}

	GetActiveMemberParams struct {
		UserID         string `json:"user_id"`
		OrganizationID string `json:"organization_id,omitempty"`
		plugin.ExtraContainer
	}

	GetActiveMemberResult struct {
		Member *Member `json:"member"`
	}

	GetActiveMemberRoleParams struct {
		UserID         string `json:"user_id"`
		OrganizationID string `json:"organization_id,omitempty"`
		plugin.ExtraContainer
	}

	GetActiveMemberRoleResult struct {
		Role string `json:"role"`
	}

	UpdateMemberRoleParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id"`
		Role           string `json:"role"`
		InvokingUserID string `json:"invoking_user_id,omitempty"`
		plugin.ExtraContainer
	}

	UpdateMemberRoleResult struct {
		Member *Member `json:"member"`
	}

	RemoveMemberParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id"`
		InvokingUserID string `json:"invoking_user_id,omitempty"`
		plugin.ExtraContainer
	}

	RemoveMemberResult struct {
		Success bool `json:"success"`
	}

	LeaveOrganizationParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id"`
		plugin.ExtraContainer
	}

	LeaveOrganizationResult struct {
		Success bool `json:"success"`
	}

	ListMembersParams struct {
		OrganizationID string `json:"organization_id"`
		Limit          int    `json:"limit,omitempty"`
		Offset         int    `json:"offset,omitempty"`
		plugin.ExtraContainer
	}

	ListMembersResult struct {
		Members []*Member `json:"members"`
		Total   int       `json:"total"`
	}

	// Invitation Parameter & Result Structs

	CreateInvitationParams struct {
		OrganizationID string  `json:"organization_id"`
		InviterID      string  `json:"inviter_id"`
		Email          string  `json:"email"`
		Role           string  `json:"role"`
		TeamID         *string `json:"team_id,omitempty"`
		plugin.ExtraContainer
	}

	CreateInvitationResult struct {
		Invitation *Invitation `json:"invitation"`
	}

	GetInvitationParams struct {
		InvitationID string `json:"invitation_id"`
		plugin.ExtraContainer
	}

	GetInvitationResult struct {
		Invitation *Invitation `json:"invitation"`
	}

	AcceptInvitationParams struct {
		InvitationID string `json:"invitation_id"`
		UserID       string `json:"user_id"`
		plugin.ExtraContainer
	}

	AcceptInvitationResult struct {
		Invitation   *Invitation   `json:"invitation"`
		Member       *Member       `json:"member"`
		Organization *Organization `json:"organization"`
	}

	RejectInvitationParams struct {
		InvitationID string `json:"invitation_id"`
		UserID       string `json:"user_id,omitempty"`
		plugin.ExtraContainer
	}

	RejectInvitationResult struct {
		Invitation *Invitation `json:"invitation"`
	}

	CancelInvitationParams struct {
		InvitationID string `json:"invitation_id"`
		UserID       string `json:"user_id,omitempty"`
		plugin.ExtraContainer
	}

	CancelInvitationResult struct {
		Invitation *Invitation `json:"invitation"`
	}

	ListInvitationsParams struct {
		OrganizationID string            `json:"organization_id"`
		Status         *InvitationStatus `json:"status,omitempty"`
		plugin.ExtraContainer
	}

	ListInvitationsResult struct {
		Invitations []*Invitation `json:"invitations"`
	}

	ListUserInvitationsParams struct {
		Email  string            `json:"email"`
		Status *InvitationStatus `json:"status,omitempty"`
		plugin.ExtraContainer
	}

	ListUserInvitationsResult struct {
		Invitations []*Invitation `json:"invitations"`
	}

	// Team Parameter & Result Structs

	CreateTeamParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id,omitempty"`
		Name           string `json:"name"`
		plugin.ExtraContainer
	}

	CreateTeamResult struct {
		Team *Team `json:"team"`
	}

	GetTeamParams struct {
		TeamID string `json:"team_id"`
		plugin.ExtraContainer
	}

	GetTeamResult struct {
		Team *Team `json:"team"`
	}

	UpdateTeamParams struct {
		TeamID string `json:"team_id"`
		UserID string `json:"user_id,omitempty"`
		Name   string `json:"name"`
		plugin.ExtraContainer
	}

	UpdateTeamResult struct {
		Team *Team `json:"team"`
	}

	DeleteTeamParams struct {
		TeamID string `json:"team_id"`
		UserID string `json:"user_id,omitempty"`
		plugin.ExtraContainer
	}

	DeleteTeamResult struct {
		Success bool `json:"success"`
	}

	ListTeamsParams struct {
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id,omitempty"`
		plugin.ExtraContainer
	}

	ListTeamsResult struct {
		Teams []*Team `json:"teams"`
	}

	AddTeamMemberParams struct {
		TeamID         string `json:"team_id"`
		UserID         string `json:"user_id"`
		InvokingUserID string `json:"invoking_user_id,omitempty"`
		plugin.ExtraContainer
	}

	AddTeamMemberResult struct {
		TeamMember *TeamMember `json:"team_member"`
	}

	RemoveTeamMemberParams struct {
		TeamID         string `json:"team_id"`
		UserID         string `json:"user_id"`
		InvokingUserID string `json:"invoking_user_id,omitempty"`
		plugin.ExtraContainer
	}

	RemoveTeamMemberResult struct {
		Success bool `json:"success"`
	}

	ListTeamMembersParams struct {
		TeamID string `json:"team_id"`
		plugin.ExtraContainer
	}

	ListTeamMembersResult struct {
		Members []*TeamMember `json:"members"`
	}

	SetActiveTeamParams struct {
		UserID string `json:"user_id"`
		TeamID string `json:"team_id"`
		plugin.ExtraContainer
	}

	SetActiveTeamResult struct {
		Team *Team `json:"team"`
	}

	GetActiveTeamParams struct {
		UserID string `json:"user_id"`
		plugin.ExtraContainer
	}

	GetActiveTeamResult struct {
		Team *Team `json:"team"`
	}

	// Dynamic Roles Parameter & Result Structs

	CreateRoleParams struct {
		OrganizationID string              `json:"organization_id"`
		UserID         string              `json:"user_id,omitempty"`
		Role           string              `json:"role"`
		Permissions    map[string][]string `json:"permissions"`
		plugin.ExtraContainer
	}

	CreateRoleResult struct {
		Role *OrganizationRole `json:"role"`
	}

	GetRoleParams struct {
		RoleID string `json:"role_id"`
		plugin.ExtraContainer
	}

	GetRoleResult struct {
		Role *OrganizationRole `json:"role"`
	}

	UpdateRoleParams struct {
		RoleID      string              `json:"role_id"`
		UserID      string              `json:"user_id,omitempty"`
		Role        *string             `json:"role,omitempty"`
		Permissions map[string][]string `json:"permissions,omitempty"`
		plugin.ExtraContainer
	}

	UpdateRoleResult struct {
		Role *OrganizationRole `json:"role"`
	}

	DeleteRoleParams struct {
		RoleID string `json:"role_id"`
		UserID string `json:"user_id,omitempty"`
		plugin.ExtraContainer
	}

	DeleteRoleResult struct {
		Success bool `json:"success"`
	}

	ListRolesParams struct {
		OrganizationID string `json:"organization_id"`
		plugin.ExtraContainer
	}

	ListRolesResult struct {
		Roles []*OrganizationRole `json:"roles"`
	}

	HasPermissionParams struct {
		OrganizationID string      `json:"organization_id"`
		UserID         string      `json:"user_id,omitempty"`
		Role           string      `json:"role,omitempty"`
		Permissions    Permissions `json:"permissions"`
		plugin.ExtraContainer
	}

	HasPermissionResult struct {
		HasPermission bool `json:"has_permission"`
	}
)
