package customsession

// Config defines the configuration parameters for the CustomSession plugin.
type Config struct {
	// TransformFunc is an optional custom callback for dynamic session payload transformation.
	TransformFunc TransformSessionFunc

	// MutateListDeviceSessions controls whether session transformation is applied to GET /multi-session/list-device-sessions.
	// Default: false
	MutateListDeviceSessions bool

	// UserAdditionalFields contains definitions for dynamic fields on User entities.
	UserAdditionalFields []AdditionalFieldDefinition

	// SessionAdditionalFields contains definitions for dynamic fields on Session entities.
	SessionAdditionalFields []AdditionalFieldDefinition

	// FilterUnregisteredFields controls whether extra fields not explicitly registered in UserAdditionalFields/SessionAdditionalFields are omitted from response JSON.
	// Default: false
	FilterUnregisteredFields bool
}

// DefaultConfig returns a Config struct initialized with recommended defaults.
func DefaultConfig() Config {
	return Config{
		TransformFunc:            nil,
		MutateListDeviceSessions: false,
		UserAdditionalFields:     nil,
		SessionAdditionalFields:  nil,
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

// WithUserAdditionalFields registers custom additional field definitions for User entities.
func WithUserAdditionalFields(fields ...AdditionalFieldDefinition) Option {
	return func(c *Config) {
		c.UserAdditionalFields = append(c.UserAdditionalFields, fields...)
	}
}

// WithSessionAdditionalFields registers custom additional field definitions for Session entities.
func WithSessionAdditionalFields(fields ...AdditionalFieldDefinition) Option {
	return func(c *Config) {
		c.SessionAdditionalFields = append(c.SessionAdditionalFields, fields...)
	}
}

// WithFilterUnregisteredFields enables or disables strict filtering of unregistered extra fields.
func WithFilterUnregisteredFields(filter bool) Option {
	return func(c *Config) {
		c.FilterUnregisteredFields = filter
	}
}
