package saml

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/account"
)

// SAML is the strongly typed capability provided by the gomodularauth-saml module.
// Applications access it via auth.Get[plugins.SAML](a) or auth.Get[saml.SAML](a).
type SAML interface {
	// RegisterIdP provisions a new SAML Identity Provider configuration.
	RegisterIdP(ctx context.Context, in RegisterIdPInput) (*IdPConfig, error)

	// RegisterIdPFromMetadata parses and registers an IdP directly from its EntityDescriptor XML.
	RegisterIdPFromMetadata(ctx context.Context, id, orgID string, metadataXML []byte) (*IdPConfig, error)

	// GetIdP retrieves an IdP configuration by its provider identifier.
	GetIdP(ctx context.Context, id string) (*IdPConfig, error)

	// GetIdPByEntityID retrieves an IdP configuration by its unique SAML EntityID.
	GetIdPByEntityID(ctx context.Context, entityID string) (*IdPConfig, error)

	// ListIdPs returns registered IdPs, optionally scoped to an organization.
	ListIdPs(ctx context.Context, orgID string) ([]*IdPConfig, error)

	// UpdateIdP updates an existing IdP configuration.
	UpdateIdP(ctx context.Context, in UpdateIdPInput) (*IdPConfig, error)

	// DeleteIdP removes an IdP configuration.
	DeleteIdP(ctx context.Context, id string) error

	// GetSPMetadata generates the Service Provider EntityDescriptor XML.
	GetSPMetadata(ctx context.Context) ([]byte, error)

	// InitiateAuth begins an SP-initiated SAML flow, generating AuthnRequest redirect URL and tracking state.
	InitiateAuth(ctx context.Context, in InitiateAuthInput) (*InitiateAuthResult, error)

	// ProcessACS processes and verifies an incoming SAMLResponse assertion, issuing a Core Session.
	ProcessACS(ctx context.Context, in ProcessACSInput) (*AuthResult, error)

	// ListLinkedAccounts returns all SAML accounts linked to a user.
	ListLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error)

	// UnlinkAccount detaches a SAML provider from a user.
	UnlinkAccount(ctx context.Context, userID, providerID string) error
}
