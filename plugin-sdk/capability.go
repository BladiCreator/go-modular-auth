package sdk

import (
	"fmt"
	"reflect"
	"sync"
)

// CapabilityRegistry manages typed capability registrations.
type CapabilityRegistry struct {
	mu      sync.RWMutex
	entries map[reflect.Type]capabilityEntry
}

type capabilityEntry struct {
	module string
	value  any
}

// NewCapabilityRegistry creates a new empty capability registry.
func NewCapabilityRegistry() *CapabilityRegistry {
	return &CapabilityRegistry{
		entries: make(map[reflect.Type]capabilityEntry),
	}
}

// Provide registers an implementation of capability T for a module.
func Provide[T any](r *CapabilityRegistry, module string, impl T) error {
	t := reflect.TypeFor[T]()
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.entries[t]; ok {
		return fmt.Errorf("%w: capability %s already provided by %q", ErrDuplicate, t, prev.module)
	}
	r.entries[t] = capabilityEntry{module: module, value: impl}
	return nil
}

// Lookup returns the registered capability T.
func Lookup[T any](r *CapabilityRegistry) (T, error) {
	var zero T
	t := reflect.TypeFor[T]()
	r.mu.RLock()
	e, ok := r.entries[t]
	r.mu.RUnlock()
	if !ok {
		return zero, fmt.Errorf("%w: %s", ErrNotFound, t)
	}
	return e.value.(T), nil
}
