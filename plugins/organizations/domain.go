package organizations

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-organizations/store"
)

// Role represents a member's role within an organization.
type Role = store.Role

const (
	RoleOwner  = store.RoleOwner
	RoleAdmin  = store.RoleAdmin
	RoleMember = store.RoleMember
)

// MembershipStatus indicates the lifecycle state of an organization membership.
type MembershipStatus = store.MembershipStatus

const (
	MembershipActive    = store.MembershipActive
	MembershipSuspended = store.MembershipSuspended
)

// OrganizationRecord represents an isolated multi-tenant tenant boundary entity.
type OrganizationRecord = store.Organization

// Membership represents the association between a Core User and an Organization.
type Membership = store.Membership

// Team represents a logical group of members within an organization.
type Team = store.Team

// TeamMembership represents a user's enrollment within a team.
type TeamMembership = store.TeamMembership

// Invitation represents an invitation sent to an email address to join an organization.
type Invitation = store.Invitation

// ScopedPrincipal binds an authenticated Core Principal with an Organization scope.
type ScopedPrincipal struct {
	Principal      auth.Principal
	OrganizationID string
	Membership     *Membership
}

// WithOrganizationContext returns a new context containing the target organization ID.
func WithOrganizationContext(ctx context.Context, orgID string) context.Context {
	return auth.WithOrganization(ctx, orgID)
}

// OrganizationFromContext retrieves the organization ID bound to ctx, if present.
func OrganizationFromContext(ctx context.Context) (string, bool) {
	return auth.OrganizationFrom(ctx)
}

