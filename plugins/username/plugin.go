package username

import (
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-username/cache"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "username"

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

// New creates an installable username PluginModule with optional functional configurations.
func New(opts ...Option) *Module {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Re-evaluate validator if custom min, max, or reserved were supplied
	if cfg.Validator == nil {
		cfg.Validator = DefaultValidator(cfg.MinLength, cfg.MaxLength, cfg.Reserved)
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = DefaultNormalizer(cfg.CaseSensitive)
	}

	return &Module{cfg: cfg}
}

// ID returns the module identifier.
func (m *Module) ID() string {
	return PluginID
}

// Init configures infrastructure and registers the typed Capability into GoModularAuth via plugin-sdk.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	cacheAdapter := cache.New(ctx.Cache(), m.cfg.CacheTTL)
	svc := &service{
		cfg:     m.cfg,
		ctx:     ctx,
		records: sdk.Model[Record](ctx, ModelUsernames),
		cache:   cacheAdapter,
	}

	return sdk.Provide[Capability](ctx, svc)
}
