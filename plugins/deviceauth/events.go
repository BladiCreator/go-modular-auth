package deviceauth

const (
	// EventDeviceCodeRequested is published when a new device authorization request is initiated.
	EventDeviceCodeRequested = "deviceauth:code_requested"

	// EventDeviceCodeApproved is published when an authenticated user approves a device code.
	EventDeviceCodeApproved = "eventauth:code_approved"

	// EventDeviceCodeDenied is published when a user explicitly rejects a device code request.
	EventDeviceCodeDenied = "deviceauth:code_denied"

	// EventDeviceTokenExchanged is published when an approved device code is successfully exchanged for a session token.
	EventDeviceTokenExchanged = "deviceauth:token_exchanged"
)

// DeviceCodeRequestedPayload defines the event bus payload dispatched on device code creation.
type DeviceCodeRequestedPayload struct {
	DeviceCode string  `json:"device_code"`
	UserCode   string  `json:"user_code"`
	ClientID   *string `json:"client_id,omitempty"`
	Scope      *string `json:"scope,omitempty"`
}

// DeviceCodeApprovedPayload defines the event bus payload dispatched when a user authorizes a grant.
type DeviceCodeApprovedPayload struct {
	UserCode string `json:"user_code"`
	UserID   string `json:"user_id"`
}

// DeviceCodeDeniedPayload defines the event bus payload dispatched when a user rejects a grant.
type DeviceCodeDeniedPayload struct {
	UserCode string `json:"user_code"`
}

// DeviceTokenExchangedPayload defines the event bus payload dispatched on successful token issuance.
type DeviceTokenExchangedPayload struct {
	DeviceCode   string `json:"device_code"`
	UserID       string `json:"user_id"`
	SessionToken string `json:"session_token"`
}
