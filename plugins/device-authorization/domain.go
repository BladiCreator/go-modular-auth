package deviceauth

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-device-authorization/store"
	"github.com/BladiCreator/go-modular-auth/session"
)

// DeviceStatus is an alias for the persistent store's DeviceStatus.
type DeviceStatus = store.DeviceStatus

const (
	StatusPending    = store.StatusPending
	StatusAuthorized = store.StatusAuthorized
	StatusDenied     = store.StatusDenied
	StatusConsumed   = store.StatusConsumed
)

// DeviceGrant is an alias for store.DeviceGrant.
type DeviceGrant = store.DeviceGrant

// DeviceAuthorizationRequestInput contains parameters to initiate a device authorization flow.
type DeviceAuthorizationRequestInput struct {
	// ClientID identifies the client application running on the device. Required.
	ClientID string `json:"client_id"`

	// Scope indicates the requested permission scopes.
	Scope string `json:"scope,omitempty"`

	// Metadata carries optional device or client properties (e.g. model, OS).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// DeviceAuthorizationResponse represents the response returned to the device (RFC 8628 Section 3.2).
type DeviceAuthorizationResponse struct {
	// DeviceCode is the high-entropy verification code for device polling.
	DeviceCode string `json:"device_code"`

	// UserCode is the human-friendly code entered by the user on the verification page.
	UserCode string `json:"user_code"`

	// VerificationURI is the web URL where the end user enters the UserCode.
	VerificationURI string `json:"verification_uri"`

	// VerificationURIComplete is the optional URL containing pre-filled user_code.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// ExpiresIn is the lifetime in seconds for the device_code and user_code.
	ExpiresIn int `json:"expires_in"`

	// Interval is the minimum polling interval in seconds that the device must respect.
	Interval int `json:"interval"`
}

// PollInput contains parameters for the device polling token request.
type PollInput struct {
	// DeviceCode is the secret code issued to the device. Required.
	DeviceCode string `json:"device_code"`

	// ClientID is the client application ID. Required.
	ClientID string `json:"client_id"`

	// Session holds optional metadata (IP address, User Agent) recorded with the created session.
	Session auth.SessionOptions `json:"session,omitempty"`
}

// PollResponse represents the outcome of a device token poll request.
type PollResponse struct {
	// Status indicates the current lifecycle status of the authorization request.
	Status DeviceStatus `json:"status"`

	// UserID is the subject identifier of the authorizing user when Status == StatusAuthorized or StatusConsumed.
	UserID string `json:"user_id,omitempty"`

	// Session is the newly established session when authorization is fulfilled.
	Session *session.Session `json:"session,omitempty"`

	// Token is the plaintext session token returned exactly once upon successful completion.
	Token string `json:"token,omitempty"`
}

// VerifyUserCodeInput contains parameters for the user entering the code on the web page.
type VerifyUserCodeInput struct {
	// UserCode is the code entered by the user. Required.
	UserCode string `json:"user_code"`

	// ClientIP is the caller's IP address used for rate limiting brute-force protection.
	ClientIP string `json:"client_ip,omitempty"`
}

// UserCodeVerificationResult presents grant metadata to the user consent interface.
type UserCodeVerificationResult struct {
	// GrantID is the internal grant identifier.
	GrantID string `json:"grant_id"`

	// ClientID is the client requesting authorization.
	ClientID string `json:"client_id"`

	// UserCode is the normalized user code.
	UserCode string `json:"user_code"`

	// Scope indicates requested permissions.
	Scope string `json:"scope,omitempty"`

	// Metadata contains additional context for display.
	Metadata map[string]string `json:"metadata,omitempty"`

	// ExpiresAt is the expiration instant.
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthorizeInput contains parameters for the end user approving the device request.
type AuthorizeInput struct {
	// UserCode is the target user code being authorized. Required.
	UserCode string `json:"user_code"`

	// Principal identifies the authenticated user approving the request. Required.
	Principal auth.Principal `json:"principal"`

	// Scope specifies approved scopes (can be subset of requested).
	Scope string `json:"scope,omitempty"`
}

// DenyInput contains parameters for the end user rejecting the device request.
type DenyInput struct {
	// UserCode is the target user code being denied. Required.
	UserCode string `json:"user_code"`

	// Principal identifies the authenticated user denying the request. Required.
	Principal auth.Principal `json:"principal"`
}
