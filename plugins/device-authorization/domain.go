package deviceauth

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
)

// DeviceStatus represents the lifecycle state of a device authorization grant.
type DeviceStatus string

const (
	// StatusPending indicates the authorization request is awaiting user interaction.
	StatusPending DeviceStatus = "pending"

	// StatusAuthorized indicates the user approved the request, ready for device token exchange.
	StatusAuthorized DeviceStatus = "authorized"

	// StatusDenied indicates the user rejected the authorization request.
	StatusDenied DeviceStatus = "denied"

	// StatusConsumed indicates the device code has been exchanged for credentials (single-use fulfilled).
	StatusConsumed DeviceStatus = "consumed"
)

// DeviceGrant represents the authoritative state of an RFC 8628 device authorization session.
type DeviceGrant struct {
	ID              string            `json:"id"`
	ClientID        string            `json:"client_id"`
	DeviceCodeHash  string            `json:"device_code_hash"`
	UserCode        string            `json:"user_code"`
	Status          DeviceStatus      `json:"status"`
	UserID          string            `json:"user_id,omitempty"`
	Scope           string            `json:"scope,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastPolledAt    *time.Time        `json:"last_polled_at,omitempty"`
	PollingInterval int               `json:"polling_interval"`
	FailedAttempts  int               `json:"failed_attempts"`
	AuthorizedAt    *time.Time        `json:"authorized_at,omitempty"`
	ConsumedAt      *time.Time        `json:"consumed_at,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// Expired reports whether the device grant has passed its validity window.
func (g *DeviceGrant) Expired(now time.Time) bool {
	return g != nil && !now.Before(g.ExpiresAt)
}

const (
	ModelDeviceGrants = "device_grants"
)

// RegisterSchema registers the device_grants model into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelDeviceGrants, ModelDeviceGrants, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "client_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "device_code_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "user_code", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "status", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "scope", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "last_polled_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "polling_interval", Type: schema.TypeInt64, Required: true})
	_ = m.AddField(schema.Field{Name: "failed_attempts", Type: schema.TypeInt64, Required: true})
	_ = m.AddField(schema.Field{Name: "authorized_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	m.Indexes = []schema.Index{
		{Name: "idx_device_code_hash", Fields: []string{"device_code_hash"}, Unique: true},
		{Name: "idx_device_user_code", Fields: []string{"user_code"}, Unique: true},
	}

	return s.AddModel(m)
}

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
