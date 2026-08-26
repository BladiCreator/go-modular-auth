package multisession

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const (
	// EventListDeviceSessionsBefore is emitted before querying device sessions for a set of tokens.
	EventListDeviceSessionsBefore = "multisession:list:before"

	// EventListDeviceSessionsAfter is emitted after successfully retrieving device sessions.
	EventListDeviceSessionsAfter = "multisession:list:after"

	// EventSetActiveSessionBefore is emitted before establishing a session as the primary active session.
	EventSetActiveSessionBefore = "multisession:set_active:before"

	// EventSetActiveSessionAfter is emitted after successfully activating a device session.
	EventSetActiveSessionAfter = "multisession:set_active:after"

	// EventRevokeDeviceSessionBefore is emitted before revoking a device session.
	EventRevokeDeviceSessionBefore = "multisession:revoke:before"

	// EventRevokeDeviceSessionAfter is emitted after successfully revoking a device session.
	EventRevokeDeviceSessionAfter = "multisession:revoke:after"

	// EventSessionCreated is emitted after a new multi-session is registered on a device.
	EventSessionCreated = "multisession:session_created"

	// EventSignOut is emitted when all multi-sessions registered on a device are mass-revoked during sign-out.
	EventSignOut = "multisession:sign_out"
)

// ListDeviceSessionsEventPayload contains parameter and result data associated with device session listing lifecycle events.
type ListDeviceSessionsEventPayload struct {
	Params *ListDeviceSessionsParams
	Result *ListDeviceSessionsResult
	Extra  map[string]any
}

// SetActiveSessionEventPayload contains parameter and result data associated with session activation lifecycle events.
type SetActiveSessionEventPayload struct {
	Params *SetActiveSessionParams
	Result *SetActiveSessionResult
	Extra  map[string]any
}

// RevokeDeviceSessionEventPayload contains parameter and result data associated with session revocation lifecycle events.
type RevokeDeviceSessionEventPayload struct {
	Params *RevokeDeviceSessionParams
	Result *RevokeDeviceSessionResult
	Extra  map[string]any
}

// SessionCreatedEventPayload contains entity data associated with multi-session creation events.
type SessionCreatedEventPayload struct {
	Session *entity.Session
	Extra   map[string]any
}

// SignOutEventPayload contains revoked token data associated with mass sign-out events.
type SignOutEventPayload struct {
	RevokedTokens []string
	Extra         map[string]any
}
