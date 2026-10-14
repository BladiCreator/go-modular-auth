package deviceauth

import (
	"time"
)

// Default configuration parameters according to RFC 8628 recommendations.
const (
	DefaultExpiresIn          = 10 * time.Minute
	DefaultPollingInterval    = 5 * time.Second
	DefaultSlowDownIncrement  = 5 * time.Second
	DefaultMaxFailedAttempts  = 5
	DefaultVerificationURI    = "https://example.com/device"
	DefaultRateLimitPerMinute = 10
)

// Config encapsulates configuration settings for the device authorization plugin.
type Config struct {
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               time.Duration
	PollingInterval         time.Duration
	SlowDownIncrement       time.Duration
	MaxFailedAttempts       int
	RateLimitPerMinute      int64
}

// Option configures device authorization plugin settings.
type Option func(*Config)

// WithVerificationURI sets the base verification URL where users enter their code.
func WithVerificationURI(uri string) Option {
	return func(c *Config) {
		c.VerificationURI = uri
	}
}

// WithVerificationURIComplete sets the complete verification URL format.
func WithVerificationURIComplete(uri string) Option {
	return func(c *Config) {
		c.VerificationURIComplete = uri
	}
}

// WithExpiresIn sets the validity lifetime of issued device and user codes.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		c.ExpiresIn = d
	}
}

// WithPollingInterval sets the minimum interval between device poll requests.
func WithPollingInterval(d time.Duration) Option {
	return func(c *Config) {
		c.PollingInterval = d
	}
}

// WithMaxFailedAttempts sets the maximum bad user-code attempts before locking the grant.
func WithMaxFailedAttempts(max int) Option {
	return func(c *Config) {
		c.MaxFailedAttempts = max
	}
}

// WithRateLimit sets the maximum verification requests allowed per minute per IP.
func WithRateLimit(limit int64) Option {
	return func(c *Config) {
		c.RateLimitPerMinute = limit
	}
}

func defaultConfig() Config {
	return Config{
		VerificationURI:    DefaultVerificationURI,
		ExpiresIn:          DefaultExpiresIn,
		PollingInterval:    DefaultPollingInterval,
		SlowDownIncrement:  DefaultSlowDownIncrement,
		MaxFailedAttempts:  DefaultMaxFailedAttempts,
		RateLimitPerMinute: DefaultRateLimitPerMinute,
	}
}
