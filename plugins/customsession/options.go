package customsession

// Config defines the configuration parameters for the CustomSession plugin.
type Config struct {
	// TransformFunc is an optional custom callback for dynamic session payload transformation.
	TransformFunc TransformSessionFunc

	// MutateListDeviceSessions controls whether session transformation is applied to GET /multi-session/list-device-sessions.
	// Default: false
	MutateListDeviceSessions bool

	// AllowedExtraKeys specifies which keys in session.Extra are preserved when FilterUnregisteredFields is enabled.
	AllowedExtraKeys []string

	// FilterUnregisteredFields controls whether extra fields not explicitly listed in AllowedExtraKeys are omitted from response JSON.
	// Default: false
	FilterUnregisteredFields bool
}

// DefaultConfig returns a Config struct initialized with recommended defaults.
func DefaultConfig() Config {
	return Config{
		TransformFunc:            nil,
		MutateListDeviceSessions: false,
		AllowedExtraKeys:         nil,
		FilterUnregisteredFields: false,
	}
}

// Option defines a functional option type for configuring the plugin.
type Option func(*Config)

// WithTransformFunc configures a custom dynamic transformation callback for session payloads.
func WithTransformFunc(fn TransformSessionFunc) Option {
	return func(c *Config) {
		c.TransformFunc = fn
	}
}

// WithMutateListDeviceSessions configures whether session transformation is also applied to device session listings.
func WithMutateListDeviceSessions(mutate bool) Option {
	return func(c *Config) {
		c.MutateListDeviceSessions = mutate
	}
}

// WithAllowedExtraKeys registers allowed key names for session Extra metadata filtering.
func WithAllowedExtraKeys(keys ...string) Option {
	return func(c *Config) {
		c.AllowedExtraKeys = append(c.AllowedExtraKeys, keys...)
	}
}

// WithFilterUnregisteredFields enables or disables strict filtering of unregistered extra fields.
func WithFilterUnregisteredFields(filter bool) Option {
	return func(c *Config) {
		c.FilterUnregisteredFields = filter
	}
}
