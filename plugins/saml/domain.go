package saml

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Model constants for schema registration.
const (
	ModelSAMLIdPs       = "saml_idps"
	ModelSAMLRequests   = "saml_requests"
	ModelSAMLAssertions = "saml_assertions"
)

// AttributeMapping defines how SAML attribute names map to normalized user profile attributes.
type AttributeMapping struct {
	EmailAttr     string            `json:"email_attr"`
	NameAttr      string            `json:"name_attr"`
	FirstNameAttr string            `json:"first_name_attr,omitempty"`
	LastNameAttr  string            `json:"last_name_attr,omitempty"`
	GroupsAttr    string            `json:"groups_attr,omitempty"`
	Custom        map[string]string `json:"custom,omitempty"`
}

// IdPConfig holds the configuration for a remote SAML 2.0 Identity Provider.
type IdPConfig struct {
	ID               string           `json:"id"`
	OrganizationID   string           `json:"organization_id,omitempty"`
	EntityID         string           `json:"entity_id"`
	SSOURL           string           `json:"sso_url"`
	SLOURL           string           `json:"slo_url,omitempty"`
	Certificates     []string         `json:"certificates"`
	SPEntityID       string           `json:"sp_entity_id,omitempty"`
	ACSURL           string           `json:"acs_url,omitempty"`
	NameIDFormat     string           `json:"name_id_format,omitempty"`
	SignRequest      bool             `json:"sign_request,omitempty"`
	AllowUnsolicited bool             `json:"allow_unsolicited,omitempty"`
	ClockSkew        time.Duration    `json:"clock_skew,omitempty"`
	AttributeMapping AttributeMapping `json:"attribute_mapping"`
	Enabled          bool             `json:"enabled"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// RequestSession stores ephemeral state for an in-flight SAML AuthnRequest.
type RequestSession struct {
	ID             string     `json:"id"`
	RelayState     string     `json:"relay_state"`
	ProviderID     string     `json:"provider_id"`
	OrganizationID string     `json:"organization_id,omitempty"`
	RedirectURI    string     `json:"redirect_uri,omitempty"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Expired reports whether the request session has expired relative to the given time.
func (s *RequestSession) Expired(now time.Time) bool {
	return s != nil && !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

// IsConsumed reports whether the request session has already been redeemed.
func (s *RequestSession) IsConsumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// AssertionRecord tracks processed SAML assertions to prevent replay attacks.
type AssertionRecord struct {
	ID         string    `json:"id"`
	ProviderID string    `json:"provider_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// RegisterSchema registers all database models required by the SAML plugin.
func RegisterSchema(s *schema.Schema) error {
	mIdPs := schema.NewModel(ModelSAMLIdPs, ModelSAMLIdPs, "id")
	_ = mIdPs.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mIdPs.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString})
	_ = mIdPs.AddField(schema.Field{Name: "entity_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mIdPs.AddField(schema.Field{Name: "sso_url", Type: schema.TypeString, Required: true})
	_ = mIdPs.AddField(schema.Field{Name: "slo_url", Type: schema.TypeString})
	_ = mIdPs.AddField(schema.Field{Name: "certificates", Type: schema.TypeJSON})
	_ = mIdPs.AddField(schema.Field{Name: "sp_entity_id", Type: schema.TypeString})
	_ = mIdPs.AddField(schema.Field{Name: "acs_url", Type: schema.TypeString})
	_ = mIdPs.AddField(schema.Field{Name: "name_id_format", Type: schema.TypeString})
	_ = mIdPs.AddField(schema.Field{Name: "sign_request", Type: schema.TypeBool})
	_ = mIdPs.AddField(schema.Field{Name: "allow_unsolicited", Type: schema.TypeBool})
	_ = mIdPs.AddField(schema.Field{Name: "clock_skew", Type: schema.TypeInt64})
	_ = mIdPs.AddField(schema.Field{Name: "attribute_mapping", Type: schema.TypeJSON})
	_ = mIdPs.AddField(schema.Field{Name: "enabled", Type: schema.TypeBool})
	_ = mIdPs.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = mIdPs.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	mIdPs.Indexes = []schema.Index{
		{Name: "idx_saml_idps_entity_id", Fields: []string{"entity_id"}, Unique: true},
		{Name: "idx_saml_idps_org_id", Fields: []string{"organization_id"}},
	}
	if err := s.AddModel(mIdPs); err != nil {
		return err
	}

	mReqs := schema.NewModel(ModelSAMLRequests, ModelSAMLRequests, "id")
	_ = mReqs.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mReqs.AddField(schema.Field{Name: "relay_state", Type: schema.TypeString})
	_ = mReqs.AddField(schema.Field{Name: "provider_id", Type: schema.TypeString, Required: true})
	_ = mReqs.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString})
	_ = mReqs.AddField(schema.Field{Name: "redirect_uri", Type: schema.TypeString})
	_ = mReqs.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = mReqs.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = mReqs.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	mReqs.Indexes = []schema.Index{
		{Name: "idx_saml_requests_relay_state", Fields: []string{"relay_state"}},
		{Name: "idx_saml_requests_expires", Fields: []string{"expires_at"}},
	}
	if err := s.AddModel(mReqs); err != nil {
		return err
	}

	mAsserts := schema.NewModel(ModelSAMLAssertions, ModelSAMLAssertions, "id")
	_ = mAsserts.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true, Unique: true})
	_ = mAsserts.AddField(schema.Field{Name: "provider_id", Type: schema.TypeString, Required: true})
	_ = mAsserts.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = mAsserts.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	mAsserts.Indexes = []schema.Index{
		{Name: "idx_saml_assertions_expires", Fields: []string{"expires_at"}},
	}
	return s.AddModel(mAsserts)
}

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
