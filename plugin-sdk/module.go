package sdk

import auth "github.com/BladiCreator/go-modular-auth"

// Module is the interface that every plugin module using the SDK must implement.
type Module interface {
	// ID returns the unique identifier for the plugin module.
	ID() string
	// Init initializes the plugin module within the given SDK context.
	Init(ctx *Context) error
}

// Adapt converts an sdk.Module into an auth.PluginModule acceptable by core auth.New.
func Adapt(m Module) auth.PluginModule {
	if m == nil {
		return nil
	}
	return &moduleAdapter{m: m}
}

type moduleAdapter struct {
	m Module
}

func (a *moduleAdapter) ID() string {
	return a.m.ID()
}

func (a *moduleAdapter) Init(host *auth.Host) error {
	return a.m.Init(NewContext(host))
}

func (a *moduleAdapter) Dependencies() []string {
	if d, ok := a.m.(Dependent); ok {
		return d.Dependencies()
	}
	return nil
}
