package captcha

import (
	"context"
	"strings"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Plugin implements Captcha verification middleware for go-modular-auth.
type Plugin struct {
	config   Config
	ctx      *plugin.Context
	verifier *Verifier
}

// New instantiates a new Captcha plugin configured with functional options.
func New(opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Plugin{
		config:   cfg,
		verifier: NewVerifier(),
	}
}

// ID returns the unique string identifier for the plugin ("captcha").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the global GoModularAuth context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns a copy of active plugin configuration settings.
func (p *Plugin) Config() Config {
	return p.config
}

// VerifyToken validates a captcha response token against the configured provider.
func (p *Plugin) VerifyToken(ctx context.Context, token string, remoteIP string) error {
	return p.verifier.Verify(ctx, p.config, token, remoteIP)
}

// IsProtectedPath determines whether a request path requires captcha verification.
func (p *Plugin) IsProtectedPath(path string) bool {
	cleanPath := strings.TrimSpace(path)

	// Check exempt endpoints first
	for _, exempt := range p.config.ExemptEndpoints {
		if cleanPath == exempt {
			return false
		}
	}

	// Check protected endpoints
	for _, endpoint := range p.config.Endpoints {
		if cleanPath == endpoint {
			return true
		}
		// Prefix matching for wildcard / subpath protection
		if strings.HasSuffix(endpoint, "/*") {
			prefix := strings.TrimSuffix(endpoint, "/*")
			if strings.HasPrefix(cleanPath, prefix) {
				return true
			}
		}
	}

	return false
}
