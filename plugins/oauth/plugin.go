package oauth

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// Module implements auth.PluginModule for GoModularAuth OAuth client authentication.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs a new OAuth client plugin module.
func New(opts ...Option) *Module {
	cfg := Config{
		AllowSignUp: true,
		UsePKCE:     true,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg.withDefaults()}
}

// ID returns the module's unique identifier within GoModularAuth.
func (m *Module) ID() string {
	return "oauth"
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	svc := newService(h, m.cfg)
	return auth.Provide[OAuth](h, svc)
}
