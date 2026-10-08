package apikeys

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// PluginID is the unique identifier for this plugin module in GoModularAuth.
const PluginID = "apikeys"

// Module implements auth.PluginModule for API key authentication and lifecycle management.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs an installable API keys plugin module.
func New(opts ...Option) *Module {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg.withDefaults()}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return PluginID
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	if m.cfg.Store == nil {
		return ErrStoreRequired
	}

	svc := newService(h, m.cfg)

	return auth.Provide[APIKeys](h, svc)
}
