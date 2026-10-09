package deviceauth

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "device-authorization"

// Module implements auth.PluginModule using plugin-sdk.
type Module struct {
	cfg Config
	svc *service
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable device authorization PluginModule with options.
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

// Init configures infrastructure and registers the typed Capability in GoModularAuth.
func (m *Module) Init(h *auth.Host) error {
	if m.cfg.Store == nil {
		return ErrStoreRequired
	}

	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	return sdk.Provide[DeviceAuthorization](ctx, m.svc)
}
