package username

import (
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-username/cache"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "username"

// Module implements auth.PluginModule.
type Module struct {
	cfg Config
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

// Init configures infrastructure and registers the typed Capability into GoModularAuth.
func (m *Module) Init(h *auth.Host) error {
	cacheAdapter := cache.New(h.Cache(), m.cfg.CacheTTL)
	svc := &service{
		cfg:   m.cfg,
		host:  h,
		store: m.cfg.Store,
		cache: cacheAdapter,
	}

	return auth.Provide[Capability](h, svc)
}
