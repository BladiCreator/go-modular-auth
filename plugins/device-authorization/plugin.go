package deviceauth

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "device-authorization"

// Module implements auth.PluginModule using plugin-sdk.
type Module struct {
	cfg Config
	svc *service
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// RegisterSchema registers the device_grants model into the schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

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
	ctx := sdk.NewContext(h)
	if ctx.Adapter() == nil {
		return ErrAdapterRequired
	}

	m.svc = newService(ctx, m.cfg)

	return sdk.Provide[DeviceAuthorization](ctx, m.svc)
}
