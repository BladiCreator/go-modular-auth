package multisession

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// DeviceSession pairs a Session entity with its corresponding User entity for device session listing,
// including a flag indicating whether it is the currently active primary session.
type DeviceSession struct {
	Session  entity.Session `json:"session"`
	User     entity.User    `json:"user"`
	IsActive bool           `json:"isActive"`
}

// ListDeviceSessionsParams contains input parameters for listing device sessions.
type ListDeviceSessionsParams struct {
	// Tokens is the slice of verified multi-session tokens present on the client device.
	Tokens []string `json:"tokens"`

	// ActiveToken optionally specifies the raw token string of the currently active primary session.
	ActiveToken string `json:"activeToken,omitempty"`
}

// ListDeviceSessionsResult contains the list of active device sessions and metadata.
type ListDeviceSessionsResult struct {
	// DeviceSessions is the slice of valid, non-expired sessions on the device.
	DeviceSessions []DeviceSession `json:"deviceSessions"`

	// TotalCount is the total number of valid multi-sessions found.
	TotalCount int `json:"totalCount"`

	// ActiveSession points to the currently active primary session on the device, if present in the list.
	ActiveSession *DeviceSession `json:"activeSession,omitempty"`
}

// SetActiveSessionParams contains input parameters for establishing an active device session.
type SetActiveSessionParams struct {
	// SessionToken specifies the target session token to set as active.
	SessionToken string `json:"sessionToken"`
}

// SetActiveSessionResult contains the output data after activating a session.
type SetActiveSessionResult struct {
	// DeviceSession holds the newly activated session and user details.
	DeviceSession DeviceSession `json:"deviceSession"`

	// ActiveToken holds the verified token string of the active session.
	ActiveToken string `json:"activeToken"`

	// ExpiresAt specifies when the active session expires.
	ExpiresAt time.Time `json:"expiresAt"`

	// Status indicates if the activation operation succeeded.
	Status bool `json:"status"`
}

// RevokeDeviceSessionParams contains input parameters for revoking a single session, all sessions, or all other sessions.
type RevokeDeviceSessionParams struct {
	// SessionToken specifies the target session token to revoke.
	SessionToken string `json:"sessionToken,omitempty"`

	// RevokeAll if true indicates all device sessions should be revoked.
	RevokeAll bool `json:"revokeAll,omitempty"`

	// RevokeOther if true indicates all device sessions EXCEPT the active session should be revoked.
	RevokeOther bool `json:"revokeOther,omitempty"`

	// DeviceTokens specifies the list of all multi-session tokens registered on the device.
	DeviceTokens []string `json:"deviceTokens,omitempty"`

	// ActiveTokenInReq specifies the token of the session currently marked as active in the request.
	ActiveTokenInReq string `json:"activeTokenInReq,omitempty"`
}

// RevokeDeviceSessionResult contains the output data after revoking one or more device sessions.
type RevokeDeviceSessionResult struct {
	// Status indicates if the revocation operation succeeded.
	Status bool `json:"status"`

	// RevokedToken contains the single token revoked (if single session revocation).
	RevokedToken string `json:"revokedToken,omitempty"`

	// RevokedTokens contains the list of all tokens revoked during mass/other revocation.
	RevokedTokens []string `json:"revokedTokens,omitempty"`

	// WasActive indicates whether the revoked session was the currently active session.
	WasActive bool `json:"wasActive"`

	// NewActiveSession points to the next available session to set as active, if applicable.
	NewActiveSession *entity.Session `json:"newActiveSession,omitempty"`

	// ClearActiveSession indicates whether the primary session cookie should be cleared.
	ClearActiveSession bool `json:"clearActiveSession,omitempty"`
}

// RevokeAllSessionsParams contains input parameters for revoking all sessions on a device.
type RevokeAllSessionsParams struct {
	// DeviceTokens specifies all verified multi-session tokens present on the device.
	DeviceTokens []string `json:"deviceTokens"`
}

// RevokeAllSessionsResult contains the output data after revoking all sessions on a device.
type RevokeAllSessionsResult struct {
	// Status indicates if the revocation succeeded.
	Status bool `json:"status"`

	// RevokedTokens is the list of all tokens removed from the database.
	RevokedTokens []string `json:"revokedTokens"`

	// Count is the number of sessions revoked.
	Count int `json:"count"`
}

// RevokeOtherSessionsParams contains input parameters for revoking all device sessions EXCEPT the active session.
type RevokeOtherSessionsParams struct {
	// DeviceTokens specifies all verified multi-session tokens present on the device.
	DeviceTokens []string `json:"deviceTokens"`

	// ActiveToken specifies the token of the currently active session to keep.
	ActiveToken string `json:"activeToken"`
}

// RevokeOtherSessionsResult contains the output data after revoking all other sessions.
type RevokeOtherSessionsResult struct {
	// Status indicates if the revocation succeeded.
	Status bool `json:"status"`

	// RevokedTokens is the list of non-active tokens removed from the database.
	RevokedTokens []string `json:"revokedTokens"`

	// Count is the number of non-active sessions revoked.
	Count int `json:"count"`
}

// MultiSessionConfigInfo represents public metadata regarding active plugin configuration.
type MultiSessionConfigInfo struct {
	MaximumSessions int    `json:"maximumSessions"`
	CookiePrefix    string `json:"cookiePrefix"`
}

// StatusResponse represents a simple boolean status response payload.
type StatusResponse struct {
	Status bool `json:"status"`
}
