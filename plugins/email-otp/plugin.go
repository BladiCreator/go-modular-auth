package emailotp

import (
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/email"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID is the unique identifier for this plugin module in GoModularAuth.
const PluginID = "email_otp"

// Module implements auth.PluginModule for Email OTP authentication using plugin-sdk.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs an installable Email OTP plugin module.
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
	ctx := sdk.NewContext(h)

	var sender email.Sender
	if m.cfg.EmailSender != nil {
		sender = m.cfg.EmailSender
	} else if ctx.Email() != nil {
		sender = ctx.Email()
	} else {
		return ErrEmailSenderRequired
	}

	svc := newService(ctx, m.cfg, sender)

	return sdk.Provide[EmailOTP](ctx, svc)
}
