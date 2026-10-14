package surrealdb

import (
	"context"
	"fmt"
	"time"

	surreal "github.com/surrealdb/surrealdb.go"
)

// Config specifies connection and authentication parameters for SurrealDB.
type Config struct {
	// Endpoint is the SurrealDB connection URL (e.g., "ws://localhost:8000/rpc", "http://localhost:8000").
	Endpoint string
	// Namespace is the target SurrealDB namespace.
	Namespace string
	// Database is the target SurrealDB database.
	Database string
	// Username for root, namespace, or database user.
	Username string
	// Password for root, namespace, or database user.
	Password string
	// Token is an optional JWT authentication token.
	Token string
	// Timeout specifies network timeout for initial connection.
	Timeout time.Duration
}

// Connect creates and authenticates a *surreal.DB client based on the Config.
func (c Config) Connect(ctx context.Context) (*surreal.DB, error) {
	if c.Endpoint == "" {
		return nil, fmt.Errorf("surrealdb: endpoint cannot be empty")
	}

	connCtx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		connCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	db, err := surreal.FromEndpointURLString(connCtx, c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("surrealdb: failed to connect to %s: %w", c.Endpoint, err)
	}

	if c.Namespace != "" && c.Database != "" {
		if err := db.Use(connCtx, c.Namespace, c.Database); err != nil {
			_ = db.Close(connCtx)
			return nil, fmt.Errorf("surrealdb: failed to use ns %q db %q: %w", c.Namespace, c.Database, err)
		}
	}

	if c.Token != "" {
		if err := db.Authenticate(connCtx, c.Token); err != nil {
			_ = db.Close(connCtx)
			return nil, fmt.Errorf("surrealdb: failed to authenticate with token: %w", err)
		}
	} else if c.Username != "" {
		_, err := db.SignIn(connCtx, surreal.Auth{
			Username: c.Username,
			Password: c.Password,
		})
		if err != nil {
			_ = db.Close(connCtx)
			return nil, fmt.Errorf("surrealdb: failed to sign in as %q: %w", c.Username, err)
		}
	}

	return db, nil
}
