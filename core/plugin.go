package auth

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/email"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/store"
)

// PluginModule is an installable plugin. Plugins depend on the core; the core
// never depends on concrete plugins.
//
// Init receives a Host scoped to the module, through which it registers
// hooks, subscribes to events, accesses infrastructure and provides its
// capabilities with Provide.
type PluginModule interface {
	ID() string
	Init(host *Host) error
}

// Dependent is implemented by modules that require other modules. Required
// modules are initialized first; missing ones make New fail.
type Dependent interface {
	Dependencies() []string
}

// Host is the surface exposed to a plugin module during and after Init.
type Host struct {
	a      *Auth
	module string
}

// Auth returns the engine, giving access to core operations (CreateSession,
// IssueToken, ConsumeToken, ...).
func (h *Host) Auth() *Auth { return h.a }

// ModuleID returns the ID of the module owning this host.
func (h *Host) ModuleID() string { return h.module }

// Store returns the core store adapter.
func (h *Host) Store() store.Store { return h.a.store }

// Cache returns the shared cache adapter, or nil when none is configured.
// Plugins must namespace their keys: cache.Key(h.ModuleID(), ...).
func (h *Host) Cache() cache.Cache { return h.a.cache }

// Email returns the email sender, or nil when none is configured.
func (h *Host) Email() email.Sender { return h.a.email }

// Hooks returns the workflow hooks registry.
func (h *Host) Hooks() *Hooks { return h.a.hooks }

// Events returns the event dispatcher.
func (h *Host) Events() *Events { return h.a.events }

// Logger returns a logger tagged with the module ID.
func (h *Host) Logger() *slog.Logger { return h.a.logger.With("plugin", h.module) }

// Now returns the current time according to the configured clock.
func (h *Host) Now() time.Time { return h.a.Now() }

// Provide registers impl as the capability T exposed by the module. T is
// usually an interface exported by the plugin; applications retrieve it with
// auth.Get[T](a).
func Provide[T any](h *Host, impl T) error {
	return plugin.Provide(h.a.registry, h.module, impl)
}

func (a *Auth) initPlugins(modules []PluginModule) error {
	byID := make(map[string]PluginModule, len(modules))
	for _, m := range modules {
		if m == nil {
			return fmt.Errorf("auth: nil plugin module")
		}
		if err := a.registry.AddModule(m.ID()); err != nil {
			return err
		}
		byID[m.ID()] = m
	}
	order, err := initOrder(modules, byID)
	if err != nil {
		return err
	}
	for _, m := range order {
		if err := m.Init(&Host{a: a, module: m.ID()}); err != nil {
			return fmt.Errorf("auth: init plugin %q: %w", m.ID(), err)
		}
	}
	return nil
}

// initOrder sorts modules so dependencies are initialized first, keeping the
// configured order otherwise. It rejects missing and cyclic dependencies.
func initOrder(modules []PluginModule, byID map[string]PluginModule) ([]PluginModule, error) {
	const (
		unvisited = iota
		visiting
		done
	)
	state := make(map[string]int, len(modules))
	order := make([]PluginModule, 0, len(modules))
	var visit func(m PluginModule, path []string) error
	visit = func(m PluginModule, path []string) error {
		switch state[m.ID()] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("%w: dependency cycle %v", ErrPluginDependency, append(path, m.ID()))
		}
		state[m.ID()] = visiting
		if d, ok := m.(Dependent); ok {
			for _, dep := range d.Dependencies() {
				dm, ok := byID[dep]
				if !ok {
					return fmt.Errorf("%w: %q requires %q", ErrPluginDependency, m.ID(), dep)
				}
				if err := visit(dm, append(slices.Clone(path), m.ID())); err != nil {
					return err
				}
			}
		}
		state[m.ID()] = done
		order = append(order, m)
		return nil
	}
	for _, m := range modules {
		if err := visit(m, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}
