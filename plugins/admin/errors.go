package admin

import (
	"errors"
)

var (
	// ErrUnauthorized indicates the calling Principal lacks administrative authority.
	ErrUnauthorized = errors.New("admin: unauthorized operation")

	// ErrUserNotFound indicates the target user does not exist in Core or Admin persistence.
	ErrUserNotFound = errors.New("admin: user not found")

	// ErrUserDisabled indicates the user is disabled and prohibited from authenticating.
	ErrUserDisabled = errors.New("admin: user account is disabled")

	// ErrUserAlreadyDisabled indicates the user is already in a disabled state.
	ErrUserAlreadyDisabled = errors.New("admin: user is already disabled")

	// ErrUserNotDisabled indicates the user is already active.
	ErrUserNotDisabled = errors.New("admin: user is not disabled")

	// ErrCannotDisableSelf prevents an administrator from locking their own account.
	ErrCannotDisableSelf = errors.New("admin: cannot disable own administrator account")

	// ErrCannotDeleteSelf prevents an administrator from deleting their own account.
	ErrCannotDeleteSelf = errors.New("admin: cannot delete own administrator account")

	// ErrInvalidInput indicates validation failure on input arguments.
	ErrInvalidInput = errors.New("admin: invalid input parameters")

	// ErrStoreRequired indicates that a persistent store implementation was not supplied.
	ErrStoreRequired = errors.New("admin: store is required")

	// ErrOrganizationsNotInstalled indicates organization-scoped administration was requested but Organizations plugin is not installed.
	ErrOrganizationsNotInstalled = errors.New("admin: organizations plugin not installed or configured")

	// ErrUserNotInOrganization indicates the target user does not belong to the target organization.
	ErrUserNotInOrganization = errors.New("admin: target user does not belong to specified organization")
)
