package apikeys

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names emitted by the apikeys module.
const (
	EventAPIKeyCreated       auth.EventName = "apikeys.created"
	EventAPIKeyRevoked       auth.EventName = "apikeys.revoked"
	EventAPIKeyRotated       auth.EventName = "apikeys.rotated"
	EventAPIKeyAuthenticated auth.EventName = "apikeys.authenticated"
	EventAPIKeyDeleted       auth.EventName = "apikeys.deleted"
)

// CreatedPayload is the payload published on EventAPIKeyCreated.
// Secrets and full key hashes are strictly omitted.
type CreatedPayload struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Prefix         string     `json:"prefix"`
	UserID         string     `json:"user_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	ServiceID      string     `json:"service_id,omitempty"`
	Scopes         []string   `json:"scopes,omitempty"`
	Permissions    []string   `json:"permissions,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

// RevokedPayload is the payload published on EventAPIKeyRevoked.
type RevokedPayload struct {
	ID             string    `json:"id"`
	Prefix         string    `json:"prefix"`
	UserID         string    `json:"user_id,omitempty"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ServiceID      string    `json:"service_id,omitempty"`
	RevokedAt      time.Time `json:"revoked_at"`
}

// RotatedPayload is the payload published on EventAPIKeyRotated.
type RotatedPayload struct {
	OldKeyID       string     `json:"old_key_id"`
	NewKeyID       string     `json:"new_key_id"`
	Prefix         string     `json:"prefix"`
	UserID         string     `json:"user_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	ServiceID      string     `json:"service_id,omitempty"`
	GracePeriod    *time.Time `json:"grace_period_expires_at,omitempty"`
}

// AuthenticatedPayload is the payload published on EventAPIKeyAuthenticated.
type AuthenticatedPayload struct {
	ID             string         `json:"id"`
	Prefix         string         `json:"prefix"`
	UserID         string         `json:"user_id,omitempty"`
	OrganizationID string         `json:"organization_id,omitempty"`
	ServiceID      string         `json:"service_id,omitempty"`
	IPAddress      string         `json:"ip_address,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	PrincipalType  string         `json:"principal_type"`
	Subject        string         `json:"subject"`
}

// DeletedPayload is the payload published on EventAPIKeyDeleted.
type DeletedPayload struct {
	ID             string `json:"id"`
	Prefix         string `json:"prefix"`
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
}
