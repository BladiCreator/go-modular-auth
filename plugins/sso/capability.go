package sso

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/account"
)

// SSO is the strongly typed capability provided by the gomodularauth-sso module.
// Applications access it via auth.Get[plugins.SSO](a) or auth.Get[sso.SSO](a).
type SSO interface {
	// CreateConfig provisions a new organization-scoped SSO Identity Provider configuration.
	CreateConfig(ctx context.Context, in CreateConfigInput) (*SSOConfig, error)

	// GetConfig retrieves a specific SSO configuration belonging to an organization.
	GetConfig(ctx context.Context, orgID, configID string) (*SSOConfig, error)

	// ListConfigsByOrganization returns all SSO configurations for a given organization.
	ListConfigsByOrganization(ctx context.Context, orgID string) ([]*SSOConfig, error)

	// UpdateConfig modifies an existing organization SSO configuration.
	UpdateConfig(ctx context.Context, in UpdateConfigInput) (*SSOConfig, error)

	// DeleteConfig removes an organization SSO configuration and cleans up domain mappings.
	DeleteConfig(ctx context.Context, orgID, configID string) error

	// DiscoverByEmail resolves the tenant SSO provider configured for the user's email domain.
	DiscoverByEmail(ctx context.Context, email string) (*DomainDiscoveryResult, error)

	// DiscoverByDomain looks up the tenant SSO provider configured for a raw domain.
	DiscoverByDomain(ctx context.Context, domain string) (*DomainDiscoveryResult, error)

	// InitiateSSO starts an enterprise federated login ceremony, returning redirect URL and tracking state.
	InitiateSSO(ctx context.Context, in InitiateSSOInput) (*InitiateSSOResult, error)

	// ProcessSSOCallback validates the returned IdP assertion/token and issues a Core authenticated session.
	ProcessSSOCallback(ctx context.Context, in ProcessSSOCallbackInput) (*SSOAuthResult, error)

	// LinkAccount explicitly associates an existing Core User with an enterprise SSO provider.
	LinkAccount(ctx context.Context, in LinkAccountInput) (*account.Account, error)

	// UnlinkAccount removes the federated link between a user and an organization SSO provider.
	UnlinkAccount(ctx context.Context, orgID, userID, providerID string) error

	// ListLinkedAccounts returns all federated accounts for a user within an organization.
	ListLinkedAccounts(ctx context.Context, orgID, userID string) ([]*account.Account, error)
}
