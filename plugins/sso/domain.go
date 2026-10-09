package sso

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-sso/store"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Re-export store types for idiomatic package root usage.
type Protocol = store.Protocol

const (
	ProtocolOIDC = store.ProtocolOIDC
	ProtocolSAML = store.ProtocolSAML
)

type SSOConfig = store.SSOConfig
type OIDCConfig = store.OIDCConfig
type SAMLConfig = store.SAMLConfig
type AttributeMapping = store.AttributeMapping
type SSOStateSession = store.SSOStateSession

// DomainDiscoveryResult represents the resolved tenant SSO configuration for a domain.
type DomainDiscoveryResult struct {
	Domain         string   `json:"domain"`
	OrganizationID string   `json:"organization_id"`
	ConfigID       string   `json:"config_id"`
	ConfigName     string   `json:"config_name"`
	Protocol       Protocol `json:"protocol"`
	SSOEndpoint    string   `json:"sso_endpoint"`
}

// CreateConfigInput specifies parameters for provisioning an organization SSO configuration.
type CreateConfigInput struct {
	OrganizationID   string            `json:"organization_id"`
	Name             string            `json:"name"`
	Protocol         Protocol          `json:"protocol"`
	Enabled          bool              `json:"enabled"`
	Domains          []string          `json:"domains"`
	JITEnabled       bool              `json:"jit_enabled"`
	DefaultRole      string            `json:"default_role,omitempty"`
	AutoLink         bool              `json:"auto_link"`
	OIDC             *OIDCConfig       `json:"oidc,omitempty"`
	SAML             *SAMLConfig       `json:"saml,omitempty"`
	AttributeMapping *AttributeMapping `json:"attribute_mapping,omitempty"`
}

// UpdateConfigInput specifies fields to update in an existing SSO configuration.
type UpdateConfigInput struct {
	OrganizationID   string            `json:"organization_id"`
	ConfigID         string            `json:"config_id"`
	Name             *string           `json:"name,omitempty"`
	Enabled          *bool             `json:"enabled,omitempty"`
	Domains          []string          `json:"domains,omitempty"`
	JITEnabled       *bool             `json:"jit_enabled,omitempty"`
	DefaultRole      *string           `json:"default_role,omitempty"`
	AutoLink         *bool             `json:"auto_link,omitempty"`
	OIDC             *OIDCConfig       `json:"oidc,omitempty"`
	SAML             *SAMLConfig       `json:"saml,omitempty"`
	AttributeMapping *AttributeMapping `json:"attribute_mapping,omitempty"`
}

// InitiateSSOInput defines parameters for starting an enterprise federated login.
type InitiateSSOInput struct {
	Email          string `json:"email,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ConfigID       string `json:"config_id,omitempty"`
	RedirectURI    string `json:"redirect_uri"`
	RelayState     string `json:"relay_state,omitempty"`
}

// InitiateSSOResult returns the redirect target and tracking state for the SSO ceremony.
type InitiateSSOResult struct {
	RedirectURL    string    `json:"redirect_url"`
	State          string    `json:"state"`
	OrganizationID string    `json:"organization_id"`
	ConfigID       string    `json:"config_id"`
	Protocol       Protocol  `json:"protocol"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// ProcessSSOCallbackInput contains tokens or assertions returned from the IdP.
type ProcessSSOCallbackInput struct {
	State        string              `json:"state"`
	Code         string              `json:"code,omitempty"`
	SAMLResponse string              `json:"saml_response,omitempty"`
	RedirectURI  string              `json:"redirect_uri"`
	Session      auth.SessionOptions `json:"session"`
}

// SSOAuthResult encapsulates the outcome of a successful SSO login transaction.
type SSOAuthResult struct {
	User           *user.User        `json:"user"`
	Account        *account.Account  `json:"account"`
	Session        *session.Session  `json:"session"`
	Token          string            `json:"token"`
	IsNewUser      bool              `json:"is_new_user"`
	OrganizationID string            `json:"organization_id"`
	ConfigID       string            `json:"config_id"`
	Protocol       Protocol          `json:"protocol"`
	Attributes     map[string]string `json:"attributes"`
	RawClaims      map[string]any    `json:"raw_claims,omitempty"`
}

// LinkAccountInput provides parameters to link an existing user to an SSO provider.
type LinkAccountInput struct {
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	ConfigID       string `json:"config_id"`
	ProviderID     string `json:"provider_id"`
	Email          string `json:"email"`
}
