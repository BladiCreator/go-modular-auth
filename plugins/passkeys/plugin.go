package passkey

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// PluginID is the unique identifier for this plugin module in GoModularAuth.
const PluginID = "passkey"

// Module implements auth.PluginModule for WebAuthn passkey authentication.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs an installable Passkey plugin module.
func New(opts ...Option) *Module {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return PluginID
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	cfg, err := m.cfg.withDefaults()
	if err != nil {
		return err
	}

	svc, err := newService(h, cfg)
	if err != nil {
		return err
	}

	return auth.Provide[Passkeys](h, svc)
}
