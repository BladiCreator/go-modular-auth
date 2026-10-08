package multisession

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "multisession"

// Module implements auth.PluginModule.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable multisession PluginModule with optional configurations.
func New(opts ...Option) *Module {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return PluginID
}

// Init configures infrastructure, registers hooks, and provides the typed Capability into GoModularAuth.
func (m *Module) Init(h *auth.Host) error {
	svc := newService(h, m.cfg)

	// Register hook to enforce maximum concurrent sessions before session creation
	if m.cfg.MaxConcurrentSessions > 0 {
		h.Hooks().BeforeSessionCreate(svc.onBeforeSessionCreate)
	}

	return auth.Provide[MultiSession](h, svc)
}
