package saml

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-saml/store"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

type IdPConfig = store.IdPConfig
type RequestSession = store.RequestSession
type AttributeMapping = store.AttributeMapping

// Binding denotes SAML 2.0 protocol binding profiles.
type Binding string

const (
	BindingHTTPRedirect Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPPOST     Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SAMLAssertion represents normalized attributes and claims extracted from a verified SAML assertion.
type SAMLAssertion struct {
	ID           string              `json:"id"`
	Issuer       string              `json:"issuer"`
	Subject      string              `json:"subject"`
	Format       string              `json:"format,omitempty"`
	SessionIndex string              `json:"session_index,omitempty"`
	Attributes   map[string][]string `json:"attributes"`
}

// RegisterIdPInput parameters for adding an Identity Provider.
type RegisterIdPInput struct {
	ID               string            `json:"id"`
	OrganizationID   string            `json:"organization_id,omitempty"`
	EntityID         string            `json:"entity_id"`
	SSOURL           string            `json:"sso_url"`
	SLOURL           string            `json:"slo_url,omitempty"`
	Certificates     []string          `json:"certificates"`
	SPEntityID       string            `json:"sp_entity_id,omitempty"`
	ACSURL           string            `json:"acs_url,omitempty"`
	NameIDFormat     string            `json:"name_id_format,omitempty"`
	SignRequest      bool              `json:"sign_request,omitempty"`
	AllowUnsolicited bool              `json:"allow_unsolicited,omitempty"`
	ClockSkew        time.Duration     `json:"clock_skew,omitempty"`
	AttributeMapping *AttributeMapping `json:"attribute_mapping,omitempty"`
	Enabled          bool              `json:"enabled"`
}

// UpdateIdPInput parameters for updating an existing Identity Provider.
type UpdateIdPInput struct {
	ID               string            `json:"id"`
	EntityID         *string           `json:"entity_id,omitempty"`
	SSOURL           *string           `json:"sso_url,omitempty"`
	SLOURL           *string           `json:"slo_url,omitempty"`
	Certificates     []string          `json:"certificates,omitempty"`
	SPEntityID       *string           `json:"sp_entity_id,omitempty"`
	ACSURL           *string           `json:"acs_url,omitempty"`
	NameIDFormat     *string           `json:"name_id_format,omitempty"`
	SignRequest      *bool             `json:"sign_request,omitempty"`
	AllowUnsolicited *bool             `json:"allow_unsolicited,omitempty"`
	ClockSkew        *time.Duration    `json:"clock_skew,omitempty"`
	AttributeMapping *AttributeMapping `json:"attribute_mapping,omitempty"`
	Enabled          *bool             `json:"enabled,omitempty"`
}

// InitiateAuthInput parameters for beginning an SP-initiated SAML authentication flow.
type InitiateAuthInput struct {
	ProviderID     string `json:"provider_id"`
	OrganizationID string `json:"organization_id,omitempty"`
	RedirectURI    string `json:"redirect_uri,omitempty"`
	RelayState     string `json:"relay_state,omitempty"`
	ForceAuthn     bool   `json:"force_authn,omitempty"`
}

// InitiateAuthResult provides the target redirect URL and in-flight tracking identifiers.
type InitiateAuthResult struct {
	RedirectURL string    `json:"redirect_url"`
	RequestID   string    `json:"request_id"`
	RelayState  string    `json:"relay_state"`
	Binding     Binding   `json:"binding"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ProcessACSInput holds incoming SAML Response assertion payload received at the ACS endpoint.
type ProcessACSInput struct {
	SAMLResponse string              `json:"saml_response"`
	RelayState   string              `json:"relay_state,omitempty"`
	Session      auth.SessionOptions `json:"session"`
}

// AuthResult encapsulates the outcome of a verified SAML authentication transaction.
type AuthResult struct {
	User        *user.User       `json:"user"`
	Account     *account.Account `json:"account"`
	Session     *session.Session `json:"session"`
	Token       string           `json:"token"`
	IsNewUser   bool             `json:"is_new_user"`
	ProviderID  string           `json:"provider_id"`
	Assertion   *SAMLAssertion   `json:"assertion"`
	RedirectURI string           `json:"redirect_uri,omitempty"`
}
