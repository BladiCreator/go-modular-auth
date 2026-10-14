package admin

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/plugins/organizations"
)

// Administrative action identifiers checked by the Authorizer.
const (
	ActionLookupUser         = "admin:lookup_user"
	ActionListUsers          = "admin:list_users"
	ActionDisableUser        = "admin:disable_user"
	ActionEnableUser         = "admin:enable_user"
	ActionRevokeSessions     = "admin:revoke_sessions"
	ActionResetPassword      = "admin:reset_password"
	ActionVerifyEmail        = "admin:verify_email"
	ActionInspectAccounts    = "admin:inspect_accounts"
	ActionInspectCredentials = "admin:inspect_credentials"
	ActionDeleteUser         = "admin:delete_user"
	ActionSetAdmin           = "admin:set_admin"
)

// Authorizer evaluates whether an authenticated Principal is authorized to perform an administrative action.
type Authorizer interface {
	Authorize(ctx context.Context, p auth.Principal, action string, targetUserID string) error
}

// AuthorizerFunc allows ordinary functions to act as an Authorizer.
type AuthorizerFunc func(ctx context.Context, p auth.Principal, action string, targetUserID string) error

// Authorize implements Authorizer.
func (f AuthorizerFunc) Authorize(ctx context.Context, p auth.Principal, action string, targetUserID string) error {
	return f(ctx, p, action, targetUserID)
}

// Config encapsulates configuration settings for the admin plugin.
type Config struct {
	Authorizer    Authorizer
	Organizations organizations.Organization
	CacheTTL      time.Duration
}

// Option configures administrative plugin settings.
type Option func(*Config)

// WithAuthorizer provides a custom authorization policy implementation.
func WithAuthorizer(a Authorizer) Option {
	return func(c *Config) {
		c.Authorizer = a
	}
}

// WithAuthorizerFunc provides an authorization function.
func WithAuthorizerFunc(fn func(ctx context.Context, p auth.Principal, action string, targetUserID string) error) Option {
	return func(c *Config) {
		c.Authorizer = AuthorizerFunc(fn)
	}
}

// WithOrganizations configures integration with the Organizations plugin for organization-scoped administration.
func WithOrganizations(orgs organizations.Organization) Option {
	return func(c *Config) {
		c.Organizations = orgs
	}
}

// WithCacheTTL configures the TTL for cached administrative flags.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = ttl
	}
}

func defaultConfig() Config {
	return Config{
		CacheTTL: 5 * time.Minute,
	}
}
