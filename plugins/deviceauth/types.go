package deviceauth

import "time"

// DeviceCodeStatus represents the authorization status of a device code.
type DeviceCodeStatus string

const (
	// StatusPending indicates the user has not yet approved or denied the device authorization request.
	StatusPending DeviceCodeStatus = "pending"

	// StatusApproved indicates the user has successfully authorized the device request.
	StatusApproved DeviceCodeStatus = "approved"

	// StatusDenied indicates the user has explicitly rejected the device authorization request.
	StatusDenied DeviceCodeStatus = "denied"
)

// DeviceCode represents a persistent device authorization request grant (RFC 8628).
type DeviceCode struct {
	// ID is the unique database record identifier.
	ID string `json:"id"`

	// DeviceCode is the high-entropy secret issued to the device for polling.
	DeviceCode string `json:"device_code"`

	// UserCode is the short, human-readable code presented to the user for verification.
	UserCode string `json:"user_code"`

	// UserID is the owner user's unique identifier, populated upon user authorization.
	UserID *string `json:"user_id,omitempty"`

	// ExpiresAt specifies the exact timestamp after which this device code grant is invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// Status represents the current state of authorization (pending, approved, denied).
	Status DeviceCodeStatus `json:"status"`

	// LastPolledAt records the timestamp of the most recent token polling request.
	LastPolledAt *time.Time `json:"last_polled_at,omitempty"`

	// PollingInterval specifies the minimum duration between consecutive polling attempts.
	PollingInterval time.Duration `json:"polling_interval"`

	// ClientID optionally identifies the client application requesting authorization.
	ClientID *string `json:"client_id,omitempty"`

	// Scope optionally specifies the requested access scope.
	Scope *string `json:"scope,omitempty"`

	// CreatedAt records when the device authorization grant was generated.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records when the device authorization grant state was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// RequestDeviceCodeParams holds the input parameters for requesting a device code authorization grant.
type RequestDeviceCodeParams struct {
	// ClientID identifies the client application requesting authorization.
	ClientID string `json:"client_id"`

	// UserID optionally pre-associates a user ID with the request.
	UserID *string `json:"user_id,omitempty"`

	// Scope optionally requests specific access permissions.
	Scope *string `json:"scope,omitempty"`
}

// DeviceCodeResponse represents the successful RFC 8628 response returned to the device.
type DeviceCodeResponse struct {
	// DeviceCode is the verification code issued to the client.
	DeviceCode string `json:"device_code"`

	// UserCode is the short verification code for human entry.
	UserCode string `json:"user_code"`

	// VerificationURI is the end-user verification URL on the authorization server.
	VerificationURI string `json:"verification_uri"`

	// VerificationURIComplete is the optional verification URL pre-filled with the user_code.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// ExpiresIn indicates the lifetime in seconds of the device_code and user_code.
	ExpiresIn int64 `json:"expires_in"`

	// Interval indicates the minimum number of seconds the client should wait between polling requests.
	Interval int64 `json:"interval"`
}

// ExchangeDeviceTokenParams holds parameters submitted by the device when polling for a session token.
type ExchangeDeviceTokenParams struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:device_code".
	GrantType string `json:"grant_type"`

	// DeviceCode is the device code issued in the initial authorization response.
	DeviceCode string `json:"device_code"`

	// ClientID optionally identifies the client making the request.
	ClientID *string `json:"client_id,omitempty"`
}

// TokenResponse represents a successful token issuance response following device authorization.
type TokenResponse struct {
	// AccessToken is the generated session or access token.
	AccessToken string `json:"access_token"`

	// TokenType is the token authorization scheme (typically "Bearer").
	TokenType string `json:"token_type"`

	// ExpiresIn is the session lifetime in seconds.
	ExpiresIn int64 `json:"expires_in"`

	// Scope optionally returns the granted access scope.
	Scope string `json:"scope,omitempty"`

	// UserID is the authenticated user ID associated with the session.
	UserID string `json:"user_id,omitempty"`
}

// RFCErrorResponse represents a standard OAuth 2.0 / RFC 8628 error payload.
type RFCErrorResponse struct {
	// Error is the RFC error string (e.g. "authorization_pending", "slow_down", "expired_token", "access_denied").
	Error string `json:"error"`

	// ErrorDescription provides human-readable details regarding the error.
	ErrorDescription string `json:"error_description,omitempty"`
}

// ApproveDeviceCodeParams holds input parameters when an authenticated user approves a device authorization.
type ApproveDeviceCodeParams struct {
	// UserID is the authenticated user approving the grant.
	UserID string `json:"user_id"`

	// UserCode is the user verification code submitted by the user.
	UserCode string `json:"user_code"`
}

// DenyDeviceCodeParams holds input parameters when an authenticated user rejects a device authorization.
type DenyDeviceCodeParams struct {
	// UserCode is the user verification code submitted by the user.
	UserCode string `json:"user_code"`
}
