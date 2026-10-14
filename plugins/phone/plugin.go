package phone

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID is the unique identifier for this plugin module in GoModularAuth.
const PluginID = "phone"

// Module implements auth.PluginModule for Phone identity and OTP authentication using plugin-sdk.
type Module struct {
	cfg Config
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// RegisterSchema registers the phone identity and OTP verification models in the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// New constructs an installable Phone plugin module.
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
	if m.cfg.Provider == nil {
		return ErrProviderRequired
	}

	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)

	return sdk.Provide[Phone](ctx, svc)
}
