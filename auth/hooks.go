package auth

import (
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Re-exported Hooks types and constructors for top-level developer experience.
type (
	Hooks = plugin.Hooks
)

var (
	// NewHooks creates a new native typed lifecycle hooks and event dispatcher.
	NewHooks = plugin.NewHooks

	// WithHooks configures a custom hooks dispatcher in engine configuration.
	WithHooks = config.WithHooks

	// WithAsyncHooks configures whether lifecycle hooks are dispatched asynchronously.
	WithAsyncHooks = config.WithAsyncHooks
)
