package sdk

import "context"

// Lifecycle defines optional lifecycle callbacks that a plugin module can implement.
type Lifecycle interface {
	// Start is invoked when the host system starts up.
	Start(ctx context.Context) error
	// Stop is invoked during graceful shutdown of the host system.
	Stop(ctx context.Context) error
}
