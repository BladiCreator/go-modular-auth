package organization

import (
	"context"
)

// MemberRepository defines the persistence operations for organization membership relations.
type MemberRepository interface {
	// CreateMember adds a user to an organization with an assigned role.
	CreateMember(ctx context.Context, member *Member) error

	// GetMember retrieves a membership record linking a user to an organization.
	GetMember(ctx context.Context, orgID, userID string) (*Member, error)

	// GetMemberByID retrieves a membership record by its primary key ID.
	GetMemberByID(ctx context.Context, memberID string) (*Member, error)

	// UpdateMember updates the assigned role of an organization member.
	UpdateMember(ctx context.Context, member *Member) error

	// DeleteMember removes a member from an organization.
	DeleteMember(ctx context.Context, orgID, userID string) error

	// ListMembers retrieves a paginated list of organization members with enriched user profiles.
	ListMembers(ctx context.Context, orgID string, limit, offset int) ([]*Member, int, error)

	// CountMembersByRole returns the number of members holding a specific role in an organization.
	CountMembersByRole(ctx context.Context, orgID, role string) (int, error)

	// CountMembers returns the total member count in an organization.
	CountMembers(ctx context.Context, orgID string) (int, error)
}
