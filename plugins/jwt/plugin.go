package jwt

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// Module implements auth.PluginModule for GoModularAuth JWT stateless tokens.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs a new JWT plugin module.
func New(opts ...Option) *Module {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg.withDefaults()}
}

// ID returns the module's unique identifier within GoModularAuth.
func (m *Module) ID() string {
	return "jwt"
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	svc := newService(h, m.cfg)
	return auth.Provide[JWT](h, svc)
}
