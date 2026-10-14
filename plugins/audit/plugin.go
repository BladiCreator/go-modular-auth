package audit

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "audit"

// Module implements auth.PluginModule for structured security auditing.
type Module struct {
	cfg Config
	svc *service
}

var (
	_ auth.PluginModule    = (*Module)(nil)
	_ auth.SchemaProvider  = (*Module)(nil)
)

// New creates an installable audit PluginModule with functional options.
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

// RegisterSchema contributes the audit_records model to the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// Init configures infrastructure, registers the typed Capability in GoModularAuth,
// and subscribes the audit consumer to all dispatched events.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	// Attach universal event consumer to Core and all plugin events
	h.Events().SubscribeAll(m.svc.HandleEvent)

	// Provide strongly-typed Capability
	return sdk.Provide[Audit](ctx, m.svc)
}

// Close flushes pending asynchronous records and closes background workers.
func (m *Module) Close() error {
	if m.svc != nil {
		return m.svc.Close()
	}
	return nil
}
