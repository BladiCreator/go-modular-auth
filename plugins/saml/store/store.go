// Package store defines the persistence contract for SAML 2.0 configuration, request sessions, and replay tracking.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested IdP configuration or request session was not found.
	ErrNotFound = errors.New("saml store: record not found")

	// ErrConflict indicates that an IdP configuration with this ID or EntityID already exists.
	ErrConflict = errors.New("saml store: record conflict")

	// ErrRequestConsumed indicates that the AuthnRequest state session was already used.
	ErrRequestConsumed = errors.New("saml store: request session already consumed")

	// ErrAssertionReplayed indicates that the SAML assertion ID was already processed within its validity window.
	ErrAssertionReplayed = errors.New("saml store: assertion replay detected")
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
	return s != nil && !now.Before(s.ExpiresAt)
}

// IsConsumed reports whether the request session has already been redeemed.
func (s *RequestSession) IsConsumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// Store defines the storage contract required by the SAML plugin.
type Store interface {
	// IdP Configuration
	SaveIdP(ctx context.Context, cfg *IdPConfig) error
	GetIdP(ctx context.Context, id string) (*IdPConfig, error)
	GetIdPByEntityID(ctx context.Context, entityID string) (*IdPConfig, error)
	ListIdPs(ctx context.Context, orgID string) ([]*IdPConfig, error)
	DeleteIdP(ctx context.Context, id string) error

	// In-flight Request Sessions
	SaveRequest(ctx context.Context, req *RequestSession) error
	GetRequest(ctx context.Context, id string) (*RequestSession, error)
	GetRequestByRelayState(ctx context.Context, relayState string) (*RequestSession, error)
	ConsumeRequest(ctx context.Context, id string, now time.Time) (*RequestSession, error)
	DeleteRequest(ctx context.Context, id string) error
	PurgeExpiredRequests(ctx context.Context, before time.Time) (int, error)

	// Assertion Replay Prevention
	RecordAssertion(ctx context.Context, assertionID, providerID string, expiresAt, now time.Time) error
	PurgeExpiredAssertions(ctx context.Context, before time.Time) (int, error)
}
