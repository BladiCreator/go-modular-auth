package sso

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/plugins/sso/oidc"
	"github.com/BladiCreator/go-modular-auth/plugins/sso/saml"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Model constants for schema registration.
const (
	ModelSSOConfigs        = "sso_configs"
	ModelSSODomainMappings = "sso_domain_mappings"
	ModelSSOStates         = "sso_states"
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
type OIDCConfig = oidc.OIDCConfig

// SAMLConfig contains SAML 2.0 specific parameters.
type SAMLConfig = saml.SAMLConfig

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

// DomainMapping associates a claimed email domain with its active SSO configuration.
type DomainMapping struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	OrganizationID string `json:"organization_id"`
	ConfigID       string `json:"config_id"`
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
	return s != nil && !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

// IsConsumed reports whether the state session has already been redeemed.
func (s *SSOStateSession) IsConsumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// RegisterSchema registers all database models required by the SSO plugin.
func RegisterSchema(s *schema.Schema) error {
	mConfigs := schema.NewModel(ModelSSOConfigs, ModelSSOConfigs, "id")
	_ = mConfigs.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mConfigs.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString, Required: true})
	_ = mConfigs.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = mConfigs.AddField(schema.Field{Name: "protocol", Type: schema.TypeString, Required: true})
	_ = mConfigs.AddField(schema.Field{Name: "enabled", Type: schema.TypeBool})
	_ = mConfigs.AddField(schema.Field{Name: "domains", Type: schema.TypeJSON})
	_ = mConfigs.AddField(schema.Field{Name: "jit_enabled", Type: schema.TypeBool})
	_ = mConfigs.AddField(schema.Field{Name: "default_role", Type: schema.TypeString})
	_ = mConfigs.AddField(schema.Field{Name: "auto_link", Type: schema.TypeBool})
	_ = mConfigs.AddField(schema.Field{Name: "oidc", Type: schema.TypeJSON})
	_ = mConfigs.AddField(schema.Field{Name: "saml", Type: schema.TypeJSON})
	_ = mConfigs.AddField(schema.Field{Name: "attribute_mapping", Type: schema.TypeJSON})
	_ = mConfigs.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = mConfigs.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	mConfigs.Indexes = []schema.Index{
		{Name: "idx_sso_configs_org_id", Fields: []string{"organization_id"}},
	}
	if err := s.AddModel(mConfigs); err != nil {
		return err
	}

	mDomains := schema.NewModel(ModelSSODomainMappings, ModelSSODomainMappings, "id")
	_ = mDomains.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mDomains.AddField(schema.Field{Name: "domain", Type: schema.TypeString, Required: true, Unique: true})
	_ = mDomains.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString, Required: true})
	_ = mDomains.AddField(schema.Field{Name: "config_id", Type: schema.TypeString, Required: true})
	mDomains.Indexes = []schema.Index{
		{Name: "idx_sso_domains_domain", Fields: []string{"domain"}, Unique: true},
	}
	if err := s.AddModel(mDomains); err != nil {
		return err
	}

	mStates := schema.NewModel(ModelSSOStates, ModelSSOStates, "state")
	_ = mStates.AddField(schema.Field{Name: "state", Type: schema.TypeString, Required: true, Unique: true})
	_ = mStates.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString, Required: true})
	_ = mStates.AddField(schema.Field{Name: "config_id", Type: schema.TypeString, Required: true})
	_ = mStates.AddField(schema.Field{Name: "protocol", Type: schema.TypeString, Required: true})
	_ = mStates.AddField(schema.Field{Name: "redirect_uri", Type: schema.TypeString, Required: true})
	_ = mStates.AddField(schema.Field{Name: "relay_state", Type: schema.TypeString})
	_ = mStates.AddField(schema.Field{Name: "nonce", Type: schema.TypeString})
	_ = mStates.AddField(schema.Field{Name: "code_verifier", Type: schema.TypeString})
	_ = mStates.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = mStates.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = mStates.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = mStates.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	mStates.Indexes = []schema.Index{
		{Name: "idx_sso_states_expires", Fields: []string{"expires_at"}},
	}
	return s.AddModel(mStates)
}

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
