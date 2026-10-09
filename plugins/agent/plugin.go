package agent

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-agent/store/memory"
)

const PluginID = "agent"

type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

func New(opts ...Option) *Module {
	var cfg Config
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.Store == nil {
		cfg.Store = memory.New()
	}
	return &Module{cfg: cfg}
}

func (m *Module) ID() string {
	return PluginID
}

func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg.Store)
	return sdk.Provide[AgentManager](ctx, svc)
}
