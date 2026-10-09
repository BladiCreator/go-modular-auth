package sso

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventConfigCreated is emitted when an organization SSO configuration is created.
	EventConfigCreated auth.EventName = "sso.config.created"

	// EventConfigUpdated is emitted when an organization SSO configuration is modified.
	EventConfigUpdated auth.EventName = "sso.config.updated"

	// EventConfigDeleted is emitted when an organization SSO configuration is removed.
	EventConfigDeleted auth.EventName = "sso.config.deleted"

	// EventLoginSuccess is emitted upon successful SSO authentication and session establishment.
	EventLoginSuccess auth.EventName = "sso.login.success"

	// EventLoginFailed is emitted when an SSO ceremony fails or is rejected.
	EventLoginFailed auth.EventName = "sso.login.failed"

	// EventJITProvisioned is emitted when a new Core User is auto-provisioned via SSO.
	EventJITProvisioned auth.EventName = "sso.jit.provisioned"

	// EventAccountLinked is emitted when an existing user is linked to an SSO provider.
	EventAccountLinked auth.EventName = "sso.account.linked"
)

// ConfigAuditPayload carries audit details for SSO configuration modifications.
type ConfigAuditPayload struct {
	OrganizationID string    `json:"organization_id"`
	ConfigID       string    `json:"config_id"`
	ConfigName     string    `json:"config_name"`
	Protocol       Protocol  `json:"protocol"`
	Domains        []string  `json:"domains"`
	Action         string    `json:"action"`
	Timestamp      time.Time `json:"timestamp"`
}

// LoginAuditPayload carries audit details for an SSO authentication event.
type LoginAuditPayload struct {
	OrganizationID string    `json:"organization_id"`
	ConfigID       string    `json:"config_id"`
	UserID         string    `json:"user_id,omitempty"`
	Email          string    `json:"email,omitempty"`
	Protocol       Protocol  `json:"protocol"`
	IsNewUser      bool      `json:"is_new_user"`
	Success        bool      `json:"success"`
	ErrorReason    string    `json:"error_reason,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}
