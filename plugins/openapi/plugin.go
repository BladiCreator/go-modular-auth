package openapi

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

const PluginID = "openapi"

type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

func New(opts ...Option) *Module {
	var cfg Config
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg.withDefaults()}
}

func (m *Module) ID() string {
	return PluginID
}

func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)
	return sdk.Provide[OpenAPIGenerator](ctx, svc)
}
