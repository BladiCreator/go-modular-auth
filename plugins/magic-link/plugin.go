package magiclink

import (
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/email"
)

// Module implements auth.PluginModule for GoModularAuth.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs a new magic link plugin module.
func New(opts ...Option) *Module {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg.withDefaults()}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return "magiclink"
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	var sender email.Sender
	if m.cfg.EmailSender != nil {
		sender = m.cfg.EmailSender
	} else if h.Email() != nil {
		sender = h.Email()
	} else {
		return ErrEmailSenderRequired
	}

	svc := newService(h, m.cfg, sender)

	return auth.Provide[MagicLink](h, svc)
}
