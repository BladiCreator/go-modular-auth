package access

// Config defines the configuration options for the AccessControl instance and plugin.
type Config struct {
	// MasterStatements defines the complete schema of valid resources and permitted actions.
	MasterStatements Statements

	// InitialRoles defines pre-configured roles to register upon instantiation.
	InitialRoles map[string]Statements

	// AllowWildcards determines if the '*' wildcard is recognized for blanket resource/action grants.
	AllowWildcards bool

	// StrictResources enforces that any registered role's statements must strictly exist in MasterStatements.
	StrictResources bool
}

// DefaultConfig returns the default configuration options.
func DefaultConfig() Config {
	return Config{
		MasterStatements: make(Statements),
		InitialRoles:     make(map[string]Statements),
		AllowWildcards:   true,
		StrictResources:  false,
	}
}

// Option represents a functional option for configuring AccessControl.
type Option func(*Config)

// WithMasterStatements sets the master statements schema.
func WithMasterStatements(stmts Statements) Option {
	return func(c *Config) {
		c.MasterStatements = CloneStatements(stmts)
	}
}

// WithInitialRoles registers a set of initial roles during initialization.
func WithInitialRoles(roles map[string]Statements) Option {
	return func(c *Config) {
		if c.InitialRoles == nil {
			c.InitialRoles = make(map[string]Statements)
		}
		for name, stmts := range roles {
			c.InitialRoles[name] = CloneStatements(stmts)
		}
	}
}

// WithAllowWildcards enables or disables wildcard ('*') handling for resources and actions.
func WithAllowWildcards(allow bool) Option {
	return func(c *Config) {
		c.AllowWildcards = allow
	}
}

// WithStrictResources enforces that roles cannot grant resources/actions not listed in MasterStatements.
func WithStrictResources(strict bool) Option {
	return func(c *Config) {
		c.StrictResources = strict
	}
}
