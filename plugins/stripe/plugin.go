package stripe

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "stripe"

// Module implements auth.PluginModule using plugin-sdk.
type Module struct {
	cfg Config
	svc *service
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// New creates an installable Stripe PluginModule with optional configurations.
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

// RegisterSchema contributes Stripe models to the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// Init configures infrastructure, registers hooks, and provides the typed Capability into GoModularAuth.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	// Register lifecycle hooks if auto-provisioning is enabled
	if m.cfg.AutoCreateCustomerOnSignUp {
		registerUserHooks(ctx, m.svc)
	}

	return sdk.Provide[Stripe](ctx, m.svc)
}
