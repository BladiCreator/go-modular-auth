package sdk

// Module is the interface that every plugin must implement.
type Module interface {
	// ID returns the unique identifier for the plugin module.
	ID() string
	// Init initializes the plugin module within the given context.
	Init(ctx *Context) error
}
