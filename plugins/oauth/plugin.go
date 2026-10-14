package oauth

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// Module implements auth.PluginModule for GoModularAuth OAuth client authentication using plugin-sdk.
type Module struct {
	cfg Config
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

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

// RegisterSchema registers oauth models in the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)
	return sdk.Provide[OAuth](ctx, svc)
}
