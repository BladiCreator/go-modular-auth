package organization

import (
	"context"
)

// TeamRepository defines the persistence operations for organization sub-teams and team memberships.
type TeamRepository interface {
	// CreateTeam creates a sub-team within an organization.
	CreateTeam(ctx context.Context, team *Team) error

	// GetTeamByID retrieves a team by ID.
	GetTeamByID(ctx context.Context, id string) (*Team, error)

	// UpdateTeam updates mutable team attributes.
	UpdateTeam(ctx context.Context, team *Team) error

	// DeleteTeam removes a team and unassigns members.
	DeleteTeam(ctx context.Context, id string) error

	// ListTeamsByOrgID lists all teams belonging to an organization.
	ListTeamsByOrgID(ctx context.Context, orgID string) ([]*Team, error)

	// ListTeamsByUserID lists teams in an organization to which a user belongs.
	ListTeamsByUserID(ctx context.Context, orgID, userID string) ([]*Team, error)

	// CountTeams returns the count of teams in an organization.
	CountTeams(ctx context.Context, orgID string) (int, error)

	// AddTeamMember assigns a user to a team.
	AddTeamMember(ctx context.Context, teamMember *TeamMember) error

	// RemoveTeamMember unassigns a user from a team.
	RemoveTeamMember(ctx context.Context, teamID, userID string) error

	// GetTeamMember retrieves a team member mapping record.
	GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error)

	// ListTeamMembers lists all member assignments for a team.
	ListTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error)

	// CountTeamMembers counts members assigned to a team.
	CountTeamMembers(ctx context.Context, teamID string) (int, error)
}
