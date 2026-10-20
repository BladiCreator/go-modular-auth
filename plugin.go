package auth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/email"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/schema"
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

// Lifecycle is optionally implemented by plugin modules or services that manage
// background tasks, workers, or buffers requiring graceful startup or shutdown.
type Lifecycle interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type closerLifecycle struct {
	closer io.Closer
}

func (c *closerLifecycle) Start(context.Context) error { return nil }
func (c *closerLifecycle) Stop(context.Context) error  { return c.closer.Close() }

// SchemaProvider is optionally implemented by PluginModule instances that contribute
// to the persistent database schema (registering new models or extending existing models).
type SchemaProvider interface {
	RegisterSchema(s *schema.Schema) error
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

// Adapter returns the generic storage adapter, or nil if none is configured.
func (h *Host) Adapter() adapter.Adapter { return h.a.adapter }

// Schema returns the compiled database schema, or nil if schema compilation is not active.
func (h *Host) Schema() *schema.Schema { return h.a.schema }

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

// RegisterLifecycle registers a Lifecycle callback for graceful shutdown.
func (h *Host) RegisterLifecycle(l Lifecycle) {
	h.a.registerLifecycle(l)
}

// Provide registers impl as the capability T exposed by the module. T is
// usually an interface exported by the plugin; applications retrieve it with
// auth.Get[T](a).
func Provide[T any](h *Host, impl T) error {
	if l, ok := any(impl).(Lifecycle); ok {
		h.a.registerLifecycle(l)
	} else if c, ok := any(impl).(io.Closer); ok {
		h.a.registerLifecycle(&closerLifecycle{closer: c})
	}
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

	// Schema compilation (BetterAuth pattern)
	s, err := schema.DefaultCoreSchema()
	if err != nil {
		return fmt.Errorf("auth: default core schema error: %w", err)
	}
	for _, m := range modules {
		if sp, ok := m.(SchemaProvider); ok {
			if err := sp.RegisterSchema(s); err != nil {
				return fmt.Errorf("auth: plugin %q schema registration: %w", m.ID(), err)
			}
		}
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("auth: compiled schema validation: %w", err)
	}
	a.schema = s
	if a.adapter != nil {
		if err := a.adapter.RegisterSchema(context.Background(), s); err != nil {
			return fmt.Errorf("auth: adapter register schema: %w", err)
		}
	}
	order, err := initOrder(modules, byID)
	if err != nil {
		return err
	}
	for _, m := range order {
		if l, ok := m.(Lifecycle); ok {
			a.registerLifecycle(l)
		} else if c, ok := m.(io.Closer); ok {
			a.registerLifecycle(&closerLifecycle{closer: c})
		}
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
