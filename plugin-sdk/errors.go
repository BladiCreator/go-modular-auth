package sdk

import "errors"

var (
	// ErrNotFound is returned when a requested capability or module is not found.
	ErrNotFound = errors.New("plugin-sdk: not found")
	// ErrDuplicate is returned when a module or capability is registered more than once.
	ErrDuplicate = errors.New("plugin-sdk: duplicate registration")
	// ErrPluginDependency is returned when a required plugin dependency is missing or cyclic.
	ErrPluginDependency = errors.New("plugin-sdk: dependency error")
)
