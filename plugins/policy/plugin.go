package policy

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "policy"

// Module implements auth.PluginModule for composable policy and attribute-based authorization.
type Module struct {
	cfg Config
	svc *service
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// RegisterSchema registers the policy model in the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// New creates an installable Policy PluginModule configured with options.
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

// Init configures infrastructure and registers the strongly typed Policy capability.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)
	return sdk.Provide[Policy](ctx, m.svc)
}
