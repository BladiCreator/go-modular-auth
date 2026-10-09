package openapi

type Config struct {
	Title       string
	Version     string
	Description string
}

type Option func(*Config)

func WithTitle(title string) Option {
	return func(c *Config) {
		c.Title = title
	}
}

func WithVersion(v string) Option {
	return func(c *Config) {
		c.Version = v
	}
}

func WithDescription(desc string) Option {
	return func(c *Config) {
		c.Description = desc
	}
}

func (c Config) withDefaults() Config {
	if c.Title == "" {
		c.Title = "Go Modular Auth API"
	}
	if c.Version == "" {
		c.Version = "1.0.0"
	}
	return c
}
