package multisession

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "multisession"

// Module implements auth.PluginModule using plugin-sdk.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)
var _ auth.SchemaProvider = (*Module)(nil)

// RegisterSchema registers the plugin's models into the schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

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

// Init configures infrastructure, registers hooks, and provides the typed Capability into GoModularAuth via plugin-sdk.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)

	// Register hook to enforce maximum concurrent sessions before session creation
	if m.cfg.MaxConcurrentSessions > 0 {
		ctx.Hooks().BeforeSessionCreate(svc.onBeforeSessionCreate)
	}

	return sdk.Provide[MultiSession](ctx, svc)
}
