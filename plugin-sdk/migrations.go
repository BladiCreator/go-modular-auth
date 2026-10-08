package sdk

import "context"

// Migration represents a single schema or data migration step.
type Migration struct {
	Version     int
	Description string
	Up          func(ctx context.Context) error
	Down        func(ctx context.Context) error
}

// MigrationProvider is optionally implemented by modules that require database schema migrations.
type MigrationProvider interface {
	Migrations() []Migration
}
