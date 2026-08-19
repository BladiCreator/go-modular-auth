package access

// Event topics dispatched by the Access Control plugin over the shared EventBus.
const (
	// EventAccessAuthorized is emitted when an authorization check succeeds.
	// Payload: *AccessAuthorizedEventPayload
	EventAccessAuthorized = "access:authorized"

	// EventAccessDenied is emitted when an authorization check is denied.
	// Payload: *AccessDeniedEventPayload
	EventAccessDenied = "access:denied"

	// EventRoleCreated is emitted when a new role is registered in AccessControl.
	// Payload: *RoleCreatedEventPayload
	EventRoleCreated = "access:role:created"

	// EventRoleDeleted is emitted when a role is removed from AccessControl.
	// Payload: *RoleDeletedEventPayload
	EventRoleDeleted = "access:role:deleted"
)

// AccessAuthorizedEventPayload contains context about a successful authorization evaluation.
type AccessAuthorizedEventPayload struct {
	// Roles contains the role identifiers evaluated.
	Roles []string

	// Request is the authorization request that was evaluated.
	Request AuthorizeRequest

	// Extra provides optional contextual metadata.
	Extra map[string]any
}

// AccessDeniedEventPayload contains context about a failed authorization evaluation.
type AccessDeniedEventPayload struct {
	// Roles contains the role identifiers evaluated.
	Roles []string

	// Request is the authorization request that failed.
	Request AuthorizeRequest

	// Reason describes why authorization was denied.
	Reason string

	// Extra provides optional contextual metadata.
	Extra map[string]any
}

// RoleCreatedEventPayload contains the details of a newly registered role.
type RoleCreatedEventPayload struct {
	// Role is the newly created Role instance.
	Role *Role
}

// RoleDeletedEventPayload contains the name of the deleted role.
type RoleDeletedEventPayload struct {
	// RoleName is the identifier of the removed role.
	RoleName string
}
