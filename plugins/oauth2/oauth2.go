package oauth2

import (
	"sync"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the OAuth 2.1 Provider plugin ("oauth2").
const PluginID = "oauth2"

// Plugin implements plugin.Plugin for the OAuth 2.1 & OpenID Connect Provider.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
	signer JWTSigner
	mu     sync.RWMutex
}

// New creates a new OAuth 2.1 Provider plugin with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	var signer JWTSigner = cfg.JWTSigner
	if signer == nil {
		signer = NewHMACSigner(cfg.SecretKey, "default-oauth2-hmac")
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
		signer: signer,
	}
}

// ID returns the unique identifier for the OAuth 2.1 plugin.
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the shared plugin.Context environment.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ctx = ctx
	return nil
}

// Config returns the current configuration of the plugin.
func (p *Plugin) Config() Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

// Repository returns the underlying storage repository.
func (p *Plugin) Repository() Repository {
	return p.repo
}
