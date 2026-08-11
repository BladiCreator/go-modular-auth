package organization

import (
	"context"
	"time"
)

// Functional Callback Types

// AllowOrgCreationFunc defines a callback to authorize whether a specific user is permitted to create new organizations.
type AllowOrgCreationFunc func(ctx context.Context, userID string) (bool, error)

// OrgLimitFunc defines a callback returning the maximum number of organizations a user can create.
type OrgLimitFunc func(ctx context.Context, userID string) (int, error)

// MembershipLimitFunc defines a callback returning the maximum number of members an organization can have.
type MembershipLimitFunc func(ctx context.Context, orgID string) (int, error)

// InvitationLimitFunc defines a callback returning the maximum number of active pending invitations for an organization.
type InvitationLimitFunc func(ctx context.Context, orgID string) (int, error)

// MaxTeamsFunc defines a callback returning the maximum number of teams an organization can create.
type MaxTeamsFunc func(ctx context.Context, orgID string) (int, error)

// MaxMembersPerTeamFunc defines a callback returning the maximum number of members a team can hold.
type MaxMembersPerTeamFunc func(ctx context.Context, teamID string) (int, error)

// MaxRolesFunc defines a callback returning the maximum number of dynamic roles an organization can configure.
type MaxRolesFunc func(ctx context.Context, orgID string) (int, error)

// InvitationEmailData holds payload information passed to SendInvitationEmailFunc when an invitation is dispatched.
type InvitationEmailData struct {
	// Invitation is the newly created invitation record.
	Invitation *Invitation

	// Organization is the organization domain record.
	Organization *Organization

	// InviterID is the user ID of the inviter.
	InviterID string

	// InviterEmail is the email of the inviter if resolved.
	InviterEmail string

	// InviterName is the display name of the inviter if resolved.
	InviterName string
}

// SendInvitationEmailFunc defines a delivery callback to dispatch invitation emails via external email services (SMTP, Resend, etc.).
type SendInvitationEmailFunc func(ctx context.Context, data InvitationEmailData) error

// Config holds all configuration settings and callbacks for the Organization plugin.
type Config struct {
	// AllowUserToCreateOrganization determines whether a user is authorized to create a new organization.
	AllowUserToCreateOrganization AllowOrgCreationFunc

	// OrganizationLimit restricts the maximum number of organizations a user can create.
	OrganizationLimit OrgLimitFunc

	// CreatorRole specifies the initial role assigned to the user creating an organization (default: "owner").
	CreatorRole string

	// MembershipLimit restricts the maximum number of members per organization.
	MembershipLimit MembershipLimitFunc

	// InvitationExpiresIn defines the validity duration for issued member invitations (default: 48 hours).
	InvitationExpiresIn time.Duration

	// InvitationLimit restricts the maximum number of pending invitations per organization.
	InvitationLimit InvitationLimitFunc

	// CancelPendingInvitationsOnReInvite automatically cancels previous pending invitations when re-inviting the same email.
	CancelPendingInvitationsOnReInvite bool

	// RequireEmailVerificationOnInvitation enforces that the invited recipient email must be verified.
	RequireEmailVerificationOnInvitation bool

	// SendInvitationEmail is an optional delivery callback invoked whenever an invitation is created.
	SendInvitationEmail SendInvitationEmailFunc

	// TeamsEnabled enables the sub-module for organizational teams and team memberships.
	TeamsEnabled bool

	// DefaultTeamEnabled automatically creates an initial default team upon organization creation.
	DefaultTeamEnabled bool

	// AllowRemovingAllTeams permits deleting all teams in an organization (default: true).
	AllowRemovingAllTeams bool

	// MaximumTeams restricts the maximum number of teams per organization.
	MaximumTeams MaxTeamsFunc

	// MaximumMembersPerTeam restricts the maximum number of members per team.
	MaximumMembersPerTeam MaxMembersPerTeamFunc

	// DynamicAccessControlEnabled enables database-persisted dynamic roles and custom permission matrices.
	DynamicAccessControlEnabled bool

	// MaximumRolesPerOrganization restricts the maximum number of dynamic roles per organization.
	MaximumRolesPerOrganization MaxRolesFunc

	// CustomRoles defines static custom roles and their granted permission matrices.
	CustomRoles map[string]Permissions
}

// DefaultConfig returns baseline production-ready defaults for the Organization plugin.
func DefaultConfig() Config {
	return Config{
		CreatorRole:         RoleOwner,
		InvitationExpiresIn: 48 * time.Hour,
		AllowRemovingAllTeams: true,
		OrganizationLimit: func(ctx context.Context, userID string) (int, error) {
			return 10, nil
		},
		MembershipLimit: func(ctx context.Context, orgID string) (int, error) {
			return 100, nil
		},
		InvitationLimit: func(ctx context.Context, orgID string) (int, error) {
			return 100, nil
		},
		MaximumTeams: func(ctx context.Context, orgID string) (int, error) {
			return 20, nil
		},
		MaximumMembersPerTeam: func(ctx context.Context, teamID string) (int, error) {
			return 50, nil
		},
		MaximumRolesPerOrganization: func(ctx context.Context, orgID string) (int, error) {
			return 20, nil
		},
	}
}

// Option configures the Organization plugin.
type Option func(*Config)

// WithCreatorRole sets the default role assigned to the user creating an organization.
func WithCreatorRole(role string) Option {
	return func(c *Config) {
		if role != "" {
			c.CreatorRole = role
		}
	}
}

// WithInvitationExpiresIn sets the expiration duration for issued member invitations.
func WithInvitationExpiresIn(duration time.Duration) Option {
	return func(c *Config) {
		if duration > 0 {
			c.InvitationExpiresIn = duration
		}
	}
}

// WithMembershipLimit sets a static maximum limit of members per organization.
func WithMembershipLimit(limit int) Option {
	return func(c *Config) {
		c.MembershipLimit = func(ctx context.Context, orgID string) (int, error) {
			return limit, nil
		}
	}
}

// WithMembershipLimitFunc sets a dynamic callback to calculate membership limits.
func WithMembershipLimitFunc(fn MembershipLimitFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.MembershipLimit = fn
		}
	}
}

// WithOrganizationLimit sets a static maximum number of organizations a user can create.
func WithOrganizationLimit(limit int) Option {
	return func(c *Config) {
		c.OrganizationLimit = func(ctx context.Context, userID string) (int, error) {
			return limit, nil
		}
	}
}

// WithOrganizationLimitFunc sets a dynamic callback to calculate organization creation limits per user.
func WithOrganizationLimitFunc(fn OrgLimitFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.OrganizationLimit = fn
		}
	}
}

// WithAllowUserToCreateOrganization sets a functional callback to validate organization creation permission.
func WithAllowUserToCreateOrganization(fn AllowOrgCreationFunc) Option {
	return func(c *Config) {
		c.AllowUserToCreateOrganization = fn
	}
}

// WithInvitationLimit sets a static maximum number of pending invitations per organization.
func WithInvitationLimit(limit int) Option {
	return func(c *Config) {
		c.InvitationLimit = func(ctx context.Context, orgID string) (int, error) {
			return limit, nil
		}
	}
}

// WithInvitationLimitFunc sets a dynamic callback to calculate pending invitation limits.
func WithInvitationLimitFunc(fn InvitationLimitFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.InvitationLimit = fn
		}
	}
}

// WithSendInvitationEmail configures an external delivery callback for dispatching invitation emails.
func WithSendInvitationEmail(fn SendInvitationEmailFunc) Option {
	return func(c *Config) {
		c.SendInvitationEmail = fn
	}
}

// WithTeams configures the teams sub-module, default team creation, and deletion rules.
func WithTeams(enabled, defaultTeam, allowRemovingAll bool) Option {
	return func(c *Config) {
		c.TeamsEnabled = enabled
		c.DefaultTeamEnabled = defaultTeam
		c.AllowRemovingAllTeams = allowRemovingAll
	}
}

// WithTeamsLimits sets dynamic callbacks for team and team-membership limits.
func WithTeamsLimits(maxTeams MaxTeamsFunc, maxMembers MaxMembersPerTeamFunc) Option {
	return func(c *Config) {
		if maxTeams != nil {
			c.MaximumTeams = maxTeams
		}
		if maxMembers != nil {
			c.MaximumMembersPerTeam = maxMembers
		}
	}
}

// WithDynamicAccessControl enables or disables dynamic organization-scoped roles.
func WithDynamicAccessControl(enabled bool) Option {
	return func(c *Config) {
		c.DynamicAccessControlEnabled = enabled
	}
}

// WithDynamicAccessControlLimits sets dynamic callbacks for role limits per organization.
func WithDynamicAccessControlLimits(maxRoles MaxRolesFunc) Option {
	return func(c *Config) {
		if maxRoles != nil {
			c.MaximumRolesPerOrganization = maxRoles
		}
	}
}

// WithCustomRoles registers custom static roles and their permission matrices.
func WithCustomRoles(roles map[string]Permissions) Option {
	return func(c *Config) {
		c.CustomRoles = roles
	}
}

// WithCancelPendingInvitationsOnReInvite controls whether existing pending invitations are auto-canceled on re-invitations.
func WithCancelPendingInvitationsOnReInvite(cancel bool) Option {
	return func(c *Config) {
		c.CancelPendingInvitationsOnReInvite = cancel
	}
}

// WithRequireEmailVerificationOnInvitation controls whether email verification is required for invitations.
func WithRequireEmailVerificationOnInvitation(require bool) Option {
	return func(c *Config) {
		c.RequireEmailVerificationOnInvitation = require
	}
}
