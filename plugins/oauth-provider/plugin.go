package oauthprovider

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "oauth_provider"

// Module implements auth.PluginModule for GoModularAuth OAuth 2.1 Provider using plugin-sdk.
type Module struct {
	cfg Config
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// New constructs an installable OAuth 2.1 Provider plugin module.
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

// RegisterSchema registers oauth provider models in the compiled schema.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)
	return sdk.Provide[OAuthProvider](ctx, svc)
}
