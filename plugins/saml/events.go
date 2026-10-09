package saml

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventIdPRegistered is emitted when a new Identity Provider is configured.
	EventIdPRegistered auth.EventName = "saml.idp.registered"

	// EventIdPUpdated is emitted when an Identity Provider configuration is updated.
	EventIdPUpdated auth.EventName = "saml.idp.updated"

	// EventIdPDeleted is emitted when an Identity Provider configuration is removed.
	EventIdPDeleted auth.EventName = "saml.idp.deleted"

	// EventAuthenticated is emitted upon successful SAML authentication and session creation.
	EventAuthenticated auth.EventName = "saml.authenticated"

	// EventAuthenticationFailed is emitted when SAML verification fails.
	EventAuthenticationFailed auth.EventName = "saml.failed"

	// EventAccountLinked is emitted when a Core account is linked to a SAML provider.
	EventAccountLinked auth.EventName = "saml.account.linked"
)

// AuthenticatedPayload carries audit details for a successful SAML login.
type AuthenticatedPayload struct {
	UserID         string    `json:"user_id"`
	AccountID      string    `json:"account_id"`
	ProviderID     string    `json:"provider_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	Subject        string    `json:"subject"`
	IsNewUser      bool      `json:"is_new_user"`
	OccurredAt     time.Time `json:"occurred_at"`
}

// FailedPayload carries audit details for a failed SAML login.
type FailedPayload struct {
	ProviderID     string    `json:"provider_id,omitempty"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ErrorReason    string    `json:"error_reason"`
	OccurredAt     time.Time `json:"occurred_at"`
}
