package deviceauth

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Audit and lifecycle event identifiers for the Device Authorization Grant.
const (
	EventDeviceAuthStarted    auth.EventName = "deviceauth.started"
	EventDeviceAuthAuthorized auth.EventName = "deviceauth.authorized"
	EventDeviceAuthDenied     auth.EventName = "deviceauth.denied"
	EventDeviceAuthConsumed   auth.EventName = "deviceauth.consumed"
)

// DeviceAuthStartedPayload describes the initiation of a device flow.
// CRITICAL: NEVER includes the plaintext device_code in events.
type DeviceAuthStartedPayload struct {
	GrantID         string    `json:"grant_id"`
	ClientID        string    `json:"client_id"`
	UserCode        string    `json:"user_code"`
	ExpiresAt       time.Time `json:"expires_at"`
	PollingInterval int       `json:"polling_interval"`
	CreatedAt       time.Time `json:"created_at"`
}

// DeviceAuthAuthorizedPayload describes user authorization of a device grant.
type DeviceAuthAuthorizedPayload struct {
	GrantID      string    `json:"grant_id"`
	ClientID     string    `json:"client_id"`
	UserCode     string    `json:"user_code"`
	UserID       string    `json:"user_id"`
	AuthorizedAt time.Time `json:"authorized_at"`
}

// DeviceAuthDeniedPayload describes user rejection of a device grant.
type DeviceAuthDeniedPayload struct {
	GrantID  string    `json:"grant_id"`
	ClientID string    `json:"client_id"`
	UserCode string    `json:"user_code"`
	DeniedAt time.Time `json:"denied_at"`
}

// DeviceAuthConsumedPayload describes single-use token issuance for a device grant.
type DeviceAuthConsumedPayload struct {
	GrantID    string    `json:"grant_id"`
	ClientID   string    `json:"client_id"`
	UserID     string    `json:"user_id"`
	ConsumedAt time.Time `json:"consumed_at"`
}
