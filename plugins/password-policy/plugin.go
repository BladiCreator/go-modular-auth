package passwordpolicy

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "password-policy"

// Module implements auth.PluginModule using plugin-sdk and wires hooks.
type Module struct {
	cfg Config
	svc *service
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// RegisterSchema registers the password history model in the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// New creates an installable Password Policy PluginModule with optional configurations.
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

// Init configures infrastructure, attaches Core authentication hooks, and registers the capability.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	// 1. Hook BeforeSignUp: intercept weak passwords before user persistence
	if m.cfg.EnforceOnSignUp {
		h.Hooks().BeforeSignUp(func(ctx context.Context, in *auth.SignUpInput) error {
			return m.svc.ValidatePassword(ctx, in.Password, "")
		})
	}

	// 2. Hook AfterSignUp: record initial password hash into history
	h.Hooks().AfterSignUp(func(ctx context.Context, res *auth.AuthResult) {
		if res != nil && res.User != nil {
			m.svc.recordCurrentPasswordHash(ctx, res.User.ID)
		}
	})

	// 3. Event Listener: observe password changes to update history
	h.Events().Subscribe(auth.EventPasswordChanged, func(ctx context.Context, e auth.Event) {
		if e.Subject != "" {
			m.svc.recordCurrentPasswordHash(ctx, e.Subject)
		}
	})

	// 4. Register typed Capability
	return sdk.Provide[PasswordPolicy](ctx, m.svc)
}
