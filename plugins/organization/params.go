package organization

// Parameter and Result Structs

// Organization Parameter & Result Structs

type CreateOrganizationParams struct {
	UserID   string         `json:"user_id"`
	Name     string         `json:"name"`
	Slug     string         `json:"slug,omitempty"`
	Logo     string         `json:"logo,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

func (p *CreateOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CreateOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type CreateOrganizationResult struct {
	Organization *Organization `json:"organization"`
	Member       *Member       `json:"member"`
}

type GetOrganizationParams struct {
	OrganizationID string         `json:"organization_id"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *GetOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetOrganizationResult struct {
	Organization *Organization `json:"organization"`
}

type GetOrganizationBySlugParams struct {
	Slug  string         `json:"slug"`
	Extra map[string]any `json:"extra,omitempty"`
}

func (p *GetOrganizationBySlugParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetOrganizationBySlugParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetOrganizationBySlugResult struct {
	Organization *Organization `json:"organization"`
}

type GetFullOrganizationParams struct {
	OrganizationID string         `json:"organization_id"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *GetFullOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetFullOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetFullOrganizationResult struct {
	Organization *Organization `json:"organization"`
	Members      []*Member     `json:"members"`
	Invitations  []*Invitation `json:"invitations"`
	Teams        []*Team       `json:"teams,omitempty"`
}

type UpdateOrganizationParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	Name           *string        `json:"name,omitempty"`
	Slug           *string        `json:"slug,omitempty"`
	Logo           *string        `json:"logo,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *UpdateOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *UpdateOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type UpdateOrganizationResult struct {
	Organization *Organization `json:"organization"`
}

type DeleteOrganizationParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *DeleteOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *DeleteOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type DeleteOrganizationResult struct {
	Success bool `json:"success"`
}

type ListOrganizationsParams struct {
	UserID string         `json:"user_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *ListOrganizationsParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListOrganizationsParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListOrganizationsResult struct {
	Organizations []*Organization `json:"organizations"`
}

type CheckSlugParams struct {
	Slug  string         `json:"slug"`
	Extra map[string]any `json:"extra,omitempty"`
}

func (p *CheckSlugParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CheckSlugParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type CheckSlugResult struct {
	Available bool `json:"available"`
}

type SetActiveOrganizationParams struct {
	UserID         string         `json:"user_id"`
	OrganizationID string         `json:"organization_id"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *SetActiveOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *SetActiveOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type SetActiveOrganizationResult struct {
	Organization *Organization `json:"organization"`
	Member       *Member       `json:"member"`
}

type GetActiveOrganizationParams struct {
	UserID string         `json:"user_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *GetActiveOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetActiveOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetActiveOrganizationResult struct {
	Organization *Organization `json:"organization"`
	Member       *Member       `json:"member"`
}

// Member Parameter & Result Structs

type AddMemberParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id"`
	Role           string         `json:"role"`
	InvokingUserID string         `json:"invoking_user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *AddMemberParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *AddMemberParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type AddMemberResult struct {
	Member *Member `json:"member"`
}

type GetMemberParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *GetMemberParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetMemberParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetMemberResult struct {
	Member *Member `json:"member"`
}

type GetActiveMemberParams struct {
	UserID         string         `json:"user_id"`
	OrganizationID string         `json:"organization_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *GetActiveMemberParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetActiveMemberParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetActiveMemberResult struct {
	Member *Member `json:"member"`
}

type GetActiveMemberRoleParams struct {
	UserID         string         `json:"user_id"`
	OrganizationID string         `json:"organization_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *GetActiveMemberRoleParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetActiveMemberRoleParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetActiveMemberRoleResult struct {
	Role string `json:"role"`
}

type UpdateMemberRoleParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id"`
	Role           string         `json:"role"`
	InvokingUserID string         `json:"invoking_user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *UpdateMemberRoleParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *UpdateMemberRoleParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type UpdateMemberRoleResult struct {
	Member *Member `json:"member"`
}

type RemoveMemberParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id"`
	InvokingUserID string         `json:"invoking_user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *RemoveMemberParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *RemoveMemberParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type RemoveMemberResult struct {
	Success bool `json:"success"`
}

type LeaveOrganizationParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *LeaveOrganizationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *LeaveOrganizationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type LeaveOrganizationResult struct {
	Success bool `json:"success"`
}

type ListMembersParams struct {
	OrganizationID string         `json:"organization_id"`
	Limit          int            `json:"limit,omitempty"`
	Offset         int            `json:"offset,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *ListMembersParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListMembersParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListMembersResult struct {
	Members []*Member `json:"members"`
	Total   int       `json:"total"`
}

// Invitation Parameter & Result Structs

type CreateInvitationParams struct {
	OrganizationID string         `json:"organization_id"`
	InviterID      string         `json:"inviter_id"`
	Email          string         `json:"email"`
	Role           string         `json:"role"`
	TeamID         *string        `json:"team_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *CreateInvitationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CreateInvitationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type CreateInvitationResult struct {
	Invitation *Invitation `json:"invitation"`
}

type GetInvitationParams struct {
	InvitationID string         `json:"invitation_id"`
	Extra        map[string]any `json:"extra,omitempty"`
}

func (p *GetInvitationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetInvitationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetInvitationResult struct {
	Invitation *Invitation `json:"invitation"`
}

type AcceptInvitationParams struct {
	InvitationID string         `json:"invitation_id"`
	UserID       string         `json:"user_id"`
	Extra        map[string]any `json:"extra,omitempty"`
}

func (p *AcceptInvitationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *AcceptInvitationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type AcceptInvitationResult struct {
	Invitation   *Invitation   `json:"invitation"`
	Member       *Member       `json:"member"`
	Organization *Organization `json:"organization"`
}

type RejectInvitationParams struct {
	InvitationID string         `json:"invitation_id"`
	UserID       string         `json:"user_id,omitempty"`
	Extra        map[string]any `json:"extra,omitempty"`
}

func (p *RejectInvitationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *RejectInvitationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type RejectInvitationResult struct {
	Invitation *Invitation `json:"invitation"`
}

type CancelInvitationParams struct {
	InvitationID string         `json:"invitation_id"`
	UserID       string         `json:"user_id,omitempty"`
	Extra        map[string]any `json:"extra,omitempty"`
}

func (p *CancelInvitationParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CancelInvitationParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type CancelInvitationResult struct {
	Invitation *Invitation `json:"invitation"`
}

type ListInvitationsParams struct {
	OrganizationID string            `json:"organization_id"`
	Status         *InvitationStatus `json:"status,omitempty"`
	Extra          map[string]any    `json:"extra,omitempty"`
}

func (p *ListInvitationsParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListInvitationsParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListInvitationsResult struct {
	Invitations []*Invitation `json:"invitations"`
}

type ListUserInvitationsParams struct {
	Email  string            `json:"email"`
	Status *InvitationStatus `json:"status,omitempty"`
	Extra  map[string]any    `json:"extra,omitempty"`
}

func (p *ListUserInvitationsParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListUserInvitationsParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListUserInvitationsResult struct {
	Invitations []*Invitation `json:"invitations"`
}

// Team Parameter & Result Structs

type CreateTeamParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	Name           string         `json:"name"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *CreateTeamParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CreateTeamParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type CreateTeamResult struct {
	Team *Team `json:"team"`
}

type GetTeamParams struct {
	TeamID string         `json:"team_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *GetTeamParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetTeamParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetTeamResult struct {
	Team *Team `json:"team"`
}

type UpdateTeamParams struct {
	TeamID string         `json:"team_id"`
	UserID string         `json:"user_id,omitempty"`
	Name   string         `json:"name"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *UpdateTeamParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *UpdateTeamParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type UpdateTeamResult struct {
	Team *Team `json:"team"`
}

type DeleteTeamParams struct {
	TeamID string         `json:"team_id"`
	UserID string         `json:"user_id,omitempty"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *DeleteTeamParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *DeleteTeamParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type DeleteTeamResult struct {
	Success bool `json:"success"`
}

type ListTeamsParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *ListTeamsParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListTeamsParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListTeamsResult struct {
	Teams []*Team `json:"teams"`
}

type AddTeamMemberParams struct {
	TeamID         string         `json:"team_id"`
	UserID         string         `json:"user_id"`
	InvokingUserID string         `json:"invoking_user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *AddTeamMemberParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *AddTeamMemberParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type AddTeamMemberResult struct {
	TeamMember *TeamMember `json:"team_member"`
}

type RemoveTeamMemberParams struct {
	TeamID         string         `json:"team_id"`
	UserID         string         `json:"user_id"`
	InvokingUserID string         `json:"invoking_user_id,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *RemoveTeamMemberParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *RemoveTeamMemberParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type RemoveTeamMemberResult struct {
	Success bool `json:"success"`
}

type ListTeamMembersParams struct {
	TeamID string         `json:"team_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *ListTeamMembersParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListTeamMembersParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListTeamMembersResult struct {
	Members []*TeamMember `json:"members"`
}

type SetActiveTeamParams struct {
	UserID string         `json:"user_id"`
	TeamID string         `json:"team_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *SetActiveTeamParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *SetActiveTeamParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type SetActiveTeamResult struct {
	Team *Team `json:"team"`
}

type GetActiveTeamParams struct {
	UserID string         `json:"user_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *GetActiveTeamParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetActiveTeamParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetActiveTeamResult struct {
	Team *Team `json:"team"`
}

// Dynamic Roles Parameter & Result Structs

type CreateRoleParams struct {
	OrganizationID string              `json:"organization_id"`
	UserID         string              `json:"user_id,omitempty"`
	Role           string              `json:"role"`
	Permissions    map[string][]string `json:"permissions"`
	Extra          map[string]any      `json:"extra,omitempty"`
}

func (p *CreateRoleParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *CreateRoleParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type CreateRoleResult struct {
	Role *OrganizationRole `json:"role"`
}

type GetRoleParams struct {
	RoleID string         `json:"role_id"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *GetRoleParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *GetRoleParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type GetRoleResult struct {
	Role *OrganizationRole `json:"role"`
}

type UpdateRoleParams struct {
	RoleID      string              `json:"role_id"`
	UserID      string              `json:"user_id,omitempty"`
	Role        *string             `json:"role,omitempty"`
	Permissions map[string][]string `json:"permissions,omitempty"`
	Extra       map[string]any      `json:"extra,omitempty"`
}

func (p *UpdateRoleParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *UpdateRoleParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type UpdateRoleResult struct {
	Role *OrganizationRole `json:"role"`
}

type DeleteRoleParams struct {
	RoleID string         `json:"role_id"`
	UserID string         `json:"user_id,omitempty"`
	Extra  map[string]any `json:"extra,omitempty"`
}

func (p *DeleteRoleParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *DeleteRoleParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type DeleteRoleResult struct {
	Success bool `json:"success"`
}

type ListRolesParams struct {
	OrganizationID string         `json:"organization_id"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *ListRolesParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *ListRolesParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type ListRolesResult struct {
	Roles []*OrganizationRole `json:"roles"`
}

type HasPermissionParams struct {
	OrganizationID string         `json:"organization_id"`
	UserID         string         `json:"user_id,omitempty"`
	Role           string         `json:"role,omitempty"`
	Permissions    Permissions    `json:"permissions"`
	Extra          map[string]any `json:"extra,omitempty"`
}

func (p *HasPermissionParams) Set(key string, val any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = val
}

func (p *HasPermissionParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[key]
	return v, ok
}

type HasPermissionResult struct {
	HasPermission bool `json:"has_permission"`
}
