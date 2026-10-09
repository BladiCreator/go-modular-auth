// Package store defines the persistence contract for enterprise Single Sign-On (SSO) in GoModularAuth.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested SSO configuration or state session was not found.
	ErrNotFound = errors.New("sso store: record not found")

	// ErrConflict indicates that an SSO configuration or domain mapping already exists.
	ErrConflict = errors.New("sso store: record conflict")

	// ErrDomainClaimed indicates that the requested domain is already claimed by another organization.
	ErrDomainClaimed = errors.New("sso store: domain already claimed by another organization")

	// ErrStateConsumed indicates that the SSO state session was already redeemed (replay attack prevented).
	ErrStateConsumed = errors.New("sso store: state session already consumed")
)

// Protocol represents the federated authentication protocol used by an SSO provider.
type Protocol string

const (
	// ProtocolOIDC designates an OpenID Connect relying-party provider.
	ProtocolOIDC Protocol = "oidc"

	// ProtocolSAML designates a SAML 2.0 Service Provider integration.
	ProtocolSAML Protocol = "saml"
)

// AttributeMapping defines how IdP assertion attributes map to canonical user identity fields.
type AttributeMapping struct {
	EmailAttr     string            `json:"email_attr"`
	NameAttr      string            `json:"name_attr"`
	FirstNameAttr string            `json:"first_name_attr,omitempty"`
	LastNameAttr  string            `json:"last_name_attr,omitempty"`
	GroupsAttr    string            `json:"groups_attr,omitempty"`
	Custom        map[string]string `json:"custom,omitempty"`
}

// OIDCConfig contains OpenID Connect specific parameters.
type OIDCConfig struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	RedirectURI     string   `json:"redirect_uri"`
	Scopes          []string `json:"scopes"`
	DiscoveryURL    string   `json:"discovery_url,omitempty"`
	SkipIssuerCheck bool     `json:"skip_issuer_check,omitempty"`
}

// SAMLConfig contains SAML 2.0 specific parameters.
type SAMLConfig struct {
	EntityID     string   `json:"entity_id"`
	SSOURL       string   `json:"sso_url"`
	SLOURL       string   `json:"slo_url,omitempty"`
	Certificates []string `json:"certificates"`
	NameIDFormat string   `json:"name_id_format,omitempty"`
	SPEntityID   string   `json:"sp_entity_id,omitempty"`
	SPACSURL     string   `json:"sp_acs_url,omitempty"`
	SignRequest  bool     `json:"sign_request,omitempty"`
	ForceAuthn   bool     `json:"force_authn,omitempty"`
}

// SSOConfig represents an organization-scoped enterprise Identity Provider configuration.
type SSOConfig struct {
	ID               string           `json:"id"`
	OrganizationID   string           `json:"organization_id"`
	Name             string           `json:"name"`
	Protocol         Protocol         `json:"protocol"`
	Enabled          bool             `json:"enabled"`
	Domains          []string         `json:"domains"`
	JITEnabled       bool             `json:"jit_enabled"`
	DefaultRole      string           `json:"default_role"`
	AutoLink         bool             `json:"auto_link"`
	OIDC             *OIDCConfig      `json:"oidc,omitempty"`
	SAML             *SAMLConfig      `json:"saml,omitempty"`
	AttributeMapping AttributeMapping `json:"attribute_mapping"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// SSOStateSession stores ephemeral metadata for an in-flight SSO authentication transaction.
type SSOStateSession struct {
	State          string            `json:"state"`
	OrganizationID string            `json:"organization_id"`
	ConfigID       string            `json:"config_id"`
	Protocol       Protocol          `json:"protocol"`
	RedirectURI    string            `json:"redirect_uri"`
	RelayState     string            `json:"relay_state,omitempty"`
	Nonce          string            `json:"nonce"`
	CodeVerifier   string            `json:"code_verifier,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ConsumedAt     *time.Time        `json:"consumed_at,omitempty"`
	ExpiresAt      time.Time         `json:"expires_at"`
	CreatedAt      time.Time         `json:"created_at"`
}

// Expired reports whether the state session has expired relative to the given time.
func (s *SSOStateSession) Expired(now time.Time) bool {
	return s != nil && !now.Before(s.ExpiresAt)
}

// IsConsumed reports whether the state session has already been redeemed.
func (s *SSOStateSession) IsConsumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// Store defines the persistent storage contract required by the SSO plugin.
// Implementations must handle tenant-isolated configurations and atomic single-use state sessions.
type Store interface {
	// SaveConfig stores a new SSO configuration and registers its domain mappings.
	SaveConfig(ctx context.Context, cfg *SSOConfig) error

	// GetConfig retrieves an SSO configuration by its ID within an organization.
	GetConfig(ctx context.Context, orgID, configID string) (*SSOConfig, error)

	// ListConfigsByOrganization returns all SSO configurations for a specific organization.
	ListConfigsByOrganization(ctx context.Context, orgID string) ([]*SSOConfig, error)

	// UpdateConfig updates an existing SSO configuration and syncs domain mappings.
	UpdateConfig(ctx context.Context, cfg *SSOConfig) error

	// DeleteConfig removes an SSO configuration and its registered domain mappings.
	DeleteConfig(ctx context.Context, orgID, configID string) error

	// GetConfigByDomain retrieves the active SSO configuration claiming the specified domain.
	GetConfigByDomain(ctx context.Context, domain string) (*SSOConfig, error)

	// SaveState stores a new ephemeral SSO state session.
	SaveState(ctx context.Context, state *SSOStateSession) error

	// GetState retrieves a state session without consuming it.
	GetState(ctx context.Context, state string) (*SSOStateSession, error)

	// ConsumeState atomically marks a state session as consumed to prevent replay attacks.
	ConsumeState(ctx context.Context, state string, now time.Time) (*SSOStateSession, error)

	// DeleteState removes a state session by its token.
	DeleteState(ctx context.Context, state string) error

	// PurgeExpiredStates deletes expired state sessions before the given timestamp.
	PurgeExpiredStates(ctx context.Context, before time.Time) (int, error)
}
