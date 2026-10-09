package rbac

import "errors"

var (
	// ErrForbidden indicates that the principal is not authorized to perform the requested action.
	ErrForbidden = errors.New("principal is not authorized to perform this action")

	// ErrRoleNotFound indicates that the requested role does not exist.
	ErrRoleNotFound = errors.New("role not found")

	// ErrRoleAlreadyExists indicates that a role with the same name already exists.
	ErrRoleAlreadyExists = errors.New("role already exists")

	// ErrAssignmentNotFound indicates that the requested role assignment does not exist.
	ErrAssignmentNotFound = errors.New("role assignment not found")

	// ErrAssignmentAlreadyExists indicates that the role is already assigned to the target principal in the given scope.
	ErrAssignmentAlreadyExists = errors.New("role assignment already exists")

	// ErrInvalidInput indicates that one or more provided arguments failed validation.
	ErrInvalidInput = errors.New("invalid rbac input")

	// ErrInvalidScope indicates an unsupported or malformed scope value.
	ErrInvalidScope = errors.New("invalid role scope")

	// ErrPrincipalRequired indicates that a nil or empty principal was supplied for evaluation.
	ErrPrincipalRequired = errors.New("principal subject is required")

	// ErrPermissionRequired indicates that an empty permission string was supplied for evaluation.
	ErrPermissionRequired = errors.New("permission is required")

	// ErrRoleInUse indicates that a role cannot be deleted because it still has active assignments.
	ErrRoleInUse = errors.New("role is currently assigned to one or more principals")
)
