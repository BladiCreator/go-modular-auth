// Package plugin defines the foundational contracts and shared execution context for authentication plugins.
package plugin

// Plugin defines the interface that all modular authentication plugins must implement.
type Plugin interface {
	// ID returns a unique identifier for the plugin (e.g., "email-password", "two-factor").
	ID() string
	// Init initializes the plugin with the shared execution context.
	Init(ctx *Context) error
}
