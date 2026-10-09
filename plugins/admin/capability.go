package admin

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Admin defines privileged administrative operations over Core authentication state and selected plugin state.
// Every administrative operation explicitly requires an authenticated Principal and enforces authorization checks.
type Admin interface {
	// LookupUser retrieves comprehensive administrative details for a Core User by ID.
	LookupUser(ctx context.Context, p auth.Principal, userID string) (*UserDetail, error)

	// LookupUserByEmail retrieves comprehensive administrative details for a Core User by email.
	LookupUserByEmail(ctx context.Context, p auth.Principal, email string) (*UserDetail, error)

	// ListUsers returns paginated user records matching filter criteria.
	ListUsers(ctx context.Context, p auth.Principal, filter ListFilter) (*UserListResult, error)

	// DisableUser disables a user account, revokes all active sessions, and emits audit events.
	DisableUser(ctx context.Context, p auth.Principal, targetUserID string, reason string) error

	// EnableUser re-enables a disabled user account and emits audit events.
	EnableUser(ctx context.Context, p auth.Principal, targetUserID string) error

	// RevokeUserSessions immediately terminates all active sessions for a target user.
	RevokeUserSessions(ctx context.Context, p auth.Principal, targetUserID string) error

	// InitiatePasswordReset generates a single-use verification token for password reset.
	// Returns the raw verification token to send via out-of-band communication or email adapter.
	InitiatePasswordReset(ctx context.Context, p auth.Principal, targetUserID string) (string, error)

	// VerifyUserEmail marks the target user's email as verified.
	VerifyUserEmail(ctx context.Context, p auth.Principal, targetUserID string) error

	// InspectAccounts returns external provider account linkages for a target user.
	InspectAccounts(ctx context.Context, p auth.Principal, targetUserID string) ([]AccountDetail, error)

	// InspectCredentials returns sanitized credential records for a target user (NEVER exposes secrets or password hashes).
	InspectCredentials(ctx context.Context, p auth.Principal, targetUserID string) ([]CredentialDetail, error)

	// DeleteUser permanently deletes a user, their credentials, accounts, sessions, and admin metadata.
	DeleteUser(ctx context.Context, p auth.Principal, targetUserID string) error

	// SetAdminStatus assigns or revokes administrative status and role for a user.
	SetAdminStatus(ctx context.Context, p auth.Principal, targetUserID string, isAdmin bool, role string) error

	// IsUserDisabled checks if a user is currently disabled (used by hooks and auth workflows).
	IsUserDisabled(ctx context.Context, userID string) (bool, error)

	// ForOrg returns an organization-scoped administrative capability.
	// Requires the Organizations plugin to be configured.
	ForOrg(orgID string) ScopedAdmin
}

// ScopedAdmin provides organization-scoped administrative operations.
// All operations verify that the calling Principal has administrative rights in the target organization
// and that the target user belongs to the target organization.
type ScopedAdmin interface {
	// LookupUser retrieves administrative details for a user belonging to the organization.
	LookupUser(ctx context.Context, p auth.Principal, userID string) (*UserDetail, error)

	// ListUsers returns paginated user records belonging to the organization.
	ListUsers(ctx context.Context, p auth.Principal, filter ListFilter) (*UserListResult, error)

	// DisableUser disables a user within the organization context and revokes active sessions.
	DisableUser(ctx context.Context, p auth.Principal, targetUserID string, reason string) error

	// EnableUser re-enables a disabled user within the organization context.
	EnableUser(ctx context.Context, p auth.Principal, targetUserID string) error

	// RevokeUserSessions immediately terminates all active sessions for a target member.
	RevokeUserSessions(ctx context.Context, p auth.Principal, targetUserID string) error

	// InspectAccounts returns external provider account linkages for a target member.
	InspectAccounts(ctx context.Context, p auth.Principal, targetUserID string) ([]AccountDetail, error)

	// InspectCredentials returns sanitized credential records for a target member.
	InspectCredentials(ctx context.Context, p auth.Principal, targetUserID string) ([]CredentialDetail, error)

	// RemoveUser removes the user from the organization.
	RemoveUser(ctx context.Context, p auth.Principal, targetUserID string) error
}

// Capability is an alias for Admin to support standard capability discovery conventions.
type Capability = Admin
