package access

// Connector defines the logical boolean evaluation strategy between multiple permissions or resources.
type Connector string

const (
	// ConnectorAND requires that all specified conditions/actions must be satisfied.
	ConnectorAND Connector = "AND"

	// ConnectorOR requires that at least one specified condition/action must be satisfied.
	ConnectorOR Connector = "OR"
)

// Wildcard constants for granting blanket permissions.
const (
	// WildcardAll matches any resource or action when wildcards are enabled.
	WildcardAll = "*"
)

// Standard error messages matching Better Auth TypeScript specifications.
const (
	// ErrPrefixUnknownResource is the error prefix when a requested resource is not recognized under ConnectorAND.
	// Matches: "You are not allowed to access resource: <resource>"
	ErrPrefixUnknownResource = "You are not allowed to access resource: "

	// ErrPrefixUnauthorized is the error prefix when a requested action on a known resource is not allowed under ConnectorAND.
	// Matches: "unauthorized to access resource \"<resource>\""
	ErrPrefixUnauthorized = "unauthorized to access resource "

	// ErrMsgNotAuthorized is the generic error message when no resources or actions match under ConnectorOR or empty request.
	ErrMsgNotAuthorized = "Not authorized"

	// ErrMsgInvalidRequest is the error message for malformed access control requests.
	ErrMsgInvalidRequest = "Invalid access control request"
)

// Shared plugin context and extra metadata keys.
const (
	// ContextKeyAccessControl is the key used to store and retrieve the AccessControl instance from plugin.Context.
	ContextKeyAccessControl = "access:control"

	// ContextKeySubjectRoles is the context key used by context helpers to pass subject roles.
	ContextKeySubjectRoles = "access:subject:roles"

	// Extra metadata keys for audit events.
	ExtraKeyResource = "resource"
	ExtraKeyActions  = "actions"
	ExtraKeyRoles    = "roles"
	ExtraKeySubject  = "subject"
	ExtraKeyReason   = "reason"
)
