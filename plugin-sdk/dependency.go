package sdk

import (
	"fmt"
	"slices"
)

// Dependent is implemented by plugins that declare dependencies on other plugin modules.
type Dependent interface {
	Dependencies() []string
}

// ResolveInitOrder sorts modules topologically so dependencies initialize before dependents.
func ResolveInitOrder(modules []Module) ([]Module, error) {
	byID := make(map[string]Module, len(modules))
	for _, m := range modules {
		if m == nil {
			return nil, fmt.Errorf("plugin-sdk: nil module")
		}
		if _, exists := byID[m.ID()]; exists {
			return nil, fmt.Errorf("%w: module %q", ErrDuplicate, m.ID())
		}
		byID[m.ID()] = m
	}

	const (
		unvisited = iota
		visiting
		done
	)
	state := make(map[string]int, len(modules))
	order := make([]Module, 0, len(modules))

	var visit func(m Module, path []string) error
	visit = func(m Module, path []string) error {
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
