// Package plugin provides the type-keyed capability registry used by the
// GoModularAuth plugin runtime.
//
// A plugin MODULE is the installable component (organizations.New()).
// A plugin CAPABILITY is the type the application consumes
// (plugins.Organization). Modules register capabilities in the Registry;
// applications retrieve them with auth.Get[T]().
package plugin

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
)

var (
	// ErrNotFound is returned when no module provides the requested capability.
	ErrNotFound = errors.New("plugin: capability not registered")
	// ErrDuplicate is returned when a module ID or capability is registered twice.
	ErrDuplicate = errors.New("plugin: duplicate registration")
)

// Registry stores modules by ID and capabilities by their static type.
// It is safe for concurrent use.
type Registry struct {
	mu           sync.RWMutex
	modules      map[string]struct{}
	capabilities map[reflect.Type]entry
}

type entry struct {
	module string
	value  any
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		modules:      map[string]struct{}{},
		capabilities: map[reflect.Type]entry{},
	}
}

// AddModule records a module ID. IDs must be unique.
func (r *Registry) AddModule(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.modules[id]; ok {
		return fmt.Errorf("%w: module %q", ErrDuplicate, id)
	}
	r.modules[id] = struct{}{}
	return nil
}

// HasModule reports whether a module ID has been registered.
func (r *Registry) HasModule(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.modules[id]
	return ok
}

// Provide registers value as the implementation of capability T on behalf of
// module. T is usually an interface type exported by the plugin.
func Provide[T any](r *Registry, module string, value T) error {
	t := reflect.TypeFor[T]()
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.capabilities[t]; ok {
		return fmt.Errorf("%w: capability %s already provided by %q", ErrDuplicate, t, prev.module)
	}
	r.capabilities[t] = entry{module: module, value: value}
	return nil
}

// Lookup returns the implementation of capability T.
func Lookup[T any](r *Registry) (T, error) {
	var zero T
	t := reflect.TypeFor[T]()
	r.mu.RLock()
	e, ok := r.capabilities[t]
	r.mu.RUnlock()
	if !ok {
		return zero, fmt.Errorf("%w: %s", ErrNotFound, t)
	}
	return e.value.(T), nil
}
