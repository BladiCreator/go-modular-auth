package serviceaccounts

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

const PluginID = "service_accounts"

type Module struct {
	cfg Config
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

func New(opts ...Option) *Module {
	var cfg Config
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg}
}

func (m *Module) ID() string {
	return PluginID
}

func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx)
	return sdk.Provide[ServiceAccountManager](ctx, svc)
}
