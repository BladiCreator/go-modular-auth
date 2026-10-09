package organizations

import "errors"

var (
	// ErrOrganizationNotFound is returned when an organization does not exist.
	ErrOrganizationNotFound = errors.New("organizations: organization not found")

	// ErrOrganizationAlreadyExists is returned when an organization with the same slug already exists.
	ErrOrganizationAlreadyExists = errors.New("organizations: organization already exists")

	// ErrMemberNotFound is returned when a user is not a member of the organization.
	ErrMemberNotFound = errors.New("organizations: member not found")

	// ErrMemberAlreadyExists is returned when a user is already a member of the organization.
	ErrMemberAlreadyExists = errors.New("organizations: member already exists")

	// ErrCannotRemoveOwner is returned when attempting to remove or demote the organization owner.
	ErrCannotRemoveOwner = errors.New("organizations: cannot remove or demote organization owner")

	// ErrUnauthorized is returned when a principal lacks required organization-scoped authorization.
	ErrUnauthorized = errors.New("organizations: unauthorized operation")

	// ErrCrossOrganizationAccess is returned when attempting an operation across tenant boundaries.
	ErrCrossOrganizationAccess = errors.New("organizations: cross-organization access forbidden")

	// ErrTeamNotFound is returned when a team does not exist.
	ErrTeamNotFound = errors.New("organizations: team not found")

	// ErrTeamAlreadyExists is returned when a team with the same slug already exists in the organization.
	ErrTeamAlreadyExists = errors.New("organizations: team already exists")

	// ErrTeamMemberNotFound is returned when a user is not a member of the team.
	ErrTeamMemberNotFound = errors.New("organizations: team member not found")

	// ErrTeamMemberAlreadyExists is returned when a user is already in the team.
	ErrTeamMemberAlreadyExists = errors.New("organizations: team member already exists")

	// ErrInvitationNotFound is returned when an invitation does not exist.
	ErrInvitationNotFound = errors.New("organizations: invitation not found")

	// ErrInvitationExpired is returned when attempting to accept an expired invitation.
	ErrInvitationExpired = errors.New("organizations: invitation expired")

	// ErrInvitationAlreadyAccepted is returned when attempting to accept an already redeemed invitation.
	ErrInvitationAlreadyAccepted = errors.New("organizations: invitation already accepted")

	// ErrInvalidInput is returned when input validation fails.
	ErrInvalidInput = errors.New("organizations: invalid input")

	// ErrStoreRequired is returned during plugin initialization when no store is provided.
	ErrStoreRequired = errors.New("organizations: store is required")
)
