package oauth

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth/provider"
)

const (
	// DefaultStateTTL is the default validity duration for an in-flight OAuth state session (10 minutes).
	DefaultStateTTL = 10 * time.Minute
)

// Config configures the OAuth plugin module.
type Config struct {
	// Providers maps provider name to its Provider implementation.
	Providers map[string]provider.Provider

	// StateTTL is the validity duration of newly issued OAuth state sessions.
	StateTTL time.Duration

	// LinkingPolicy determines whether and how accounts are linked when email addresses collide.
	// Defaults to LinkingPolicyExplicitOnly (preventing unsafe automatic account linking).
	LinkingPolicy LinkingPolicy

	// AllowSignUp controls whether unknown OAuth users are automatically registered.
	// Defaults to true.
	AllowSignUp bool

	// AllowOrphanUser allows unlinking a provider even if it leaves the user with no remaining auth credentials.
	// Defaults to false.
	AllowOrphanUser bool

	// UsePKCE determines whether PKCE (RFC 7636) is generated and required by default.
	// Defaults to true.
	UsePKCE bool

	// Hooks provides lifecycle interceptors for OAuth operations.
	Hooks *Hooks
}

// Option customizes a Config struct.
type Option func(*Config)

// WithProvider registers a single OAuth identity provider.
func WithProvider(p provider.Provider) Option {
	return func(c *Config) {
		if c.Providers == nil {
			c.Providers = make(map[string]provider.Provider)
		}
		c.Providers[p.Name()] = p
	}
}

// WithProviders registers multiple OAuth identity providers.
func WithProviders(providers ...provider.Provider) Option {
	return func(c *Config) {
		if c.Providers == nil {
			c.Providers = make(map[string]provider.Provider)
		}
		for _, p := range providers {
			c.Providers[p.Name()] = p
		}
	}
}

// WithStateTTL configures the lifetime of in-flight state sessions.
func WithStateTTL(d time.Duration) Option {
	return func(c *Config) {
		c.StateTTL = d
	}
}

// WithLinkingPolicy configures the policy for resolving account linking collisions.
func WithLinkingPolicy(policy LinkingPolicy) Option {
	return func(c *Config) {
		c.LinkingPolicy = policy
	}
}

// WithAllowSignUp specifies whether new user registration via OAuth is allowed.
func WithAllowSignUp(allow bool) Option {
	return func(c *Config) {
		c.AllowSignUp = allow
	}
}

// WithAllowOrphanUser allows unlinking an OAuth account even if no other auth credentials remain.
func WithAllowOrphanUser(allow bool) Option {
	return func(c *Config) {
		c.AllowOrphanUser = allow
	}
}

// WithDefaultPKCE configures whether PKCE is enabled by default.
func WithDefaultPKCE(usePKCE bool) Option {
	return func(c *Config) {
		c.UsePKCE = usePKCE
	}
}

// WithHooks sets the lifecycle hooks.
func WithHooks(h *Hooks) Option {
	return func(c *Config) {
		c.Hooks = h
	}
}

func (c Config) withDefaults() Config {
	if c.Providers == nil {
		c.Providers = make(map[string]provider.Provider)
	}
	if c.StateTTL <= 0 {
		c.StateTTL = DefaultStateTTL
	}
	if c.LinkingPolicy == "" {
		c.LinkingPolicy = LinkingPolicyExplicitOnly
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	// Note: AllowSignUp default is true
	return c
}
