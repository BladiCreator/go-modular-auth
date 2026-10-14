package jwt

import (
	"time"

	jwtcache "github.com/BladiCreator/go-modular-auth-jwt/cache"
)

// Config configures the JWT plugin module.
type Config struct {
	// Issuer defines the default issuer string applied to issued tokens.
	Issuer string

	// DefaultAudience specifies the default audience list applied when claims.Audience is empty.
	DefaultAudience []string

	// DefaultTTL specifies the default token validity duration when ExpiresAt is not explicitly provided.
	DefaultTTL time.Duration

	// AllowedAlgorithms is the strict whitelist of algorithms permitted for verification.
	AllowedAlgorithms []Algorithm

	// KeyManager manages cryptographic keys, key rotation, and kid resolution.
	KeyManager KeyManager

	// Cache accelerates revocation verification lookups.
	Cache jwtcache.RevocationCache

	// Leeway provides clock skew tolerance during expiration (exp) and not-before (nbf) validation.
	Leeway time.Duration

	// Hooks provides lifecycle extension points for issue, verify, and revoke operations.
	Hooks *Hooks
}

// Option modifies a Config instance.
type Option func(*Config)

// WithIssuer configures the default issuer claim.
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		c.Issuer = issuer
	}
}

// WithDefaultAudience sets the default audience list.
func WithDefaultAudience(aud ...string) Option {
	return func(c *Config) {
		c.DefaultAudience = aud
	}
}

// WithDefaultTTL configures the fallback token validity duration.
func WithDefaultTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.DefaultTTL = ttl
		}
	}
}

// WithAllowedAlgorithms configures the strict whitelist of algorithms permitted.
func WithAllowedAlgorithms(algs ...Algorithm) Option {
	return func(c *Config) {
		c.AllowedAlgorithms = algs
	}
}

// WithKeyManager sets the KeyManager.
func WithKeyManager(km KeyManager) Option {
	return func(c *Config) {
		c.KeyManager = km
	}
}

// WithKey registers a single cryptographic key.
func WithKey(key Key) Option {
	return func(c *Config) {
		if c.KeyManager == nil {
			c.KeyManager = NewKeyManager()
		}
		_ = c.KeyManager.AddKey(key)
	}
}

// WithRevocationCache sets the revocation cache.
func WithRevocationCache(cache jwtcache.RevocationCache) Option {
	return func(c *Config) {
		c.Cache = cache
	}
}

// WithDefaultLeeway sets the default clock skew leeway duration for token verification.
func WithDefaultLeeway(leeway time.Duration) Option {
	return func(c *Config) {
		if leeway >= 0 {
			c.Leeway = leeway
		}
	}
}

// WithHooks sets the lifecycle hooks registry.
func WithHooks(hooks *Hooks) Option {
	return func(c *Config) {
		c.Hooks = hooks
	}
}

func (c Config) withDefaults() Config {
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = 15 * time.Minute
	}
	if c.Leeway <= 0 {
		c.Leeway = 1 * time.Minute
	}
	if len(c.AllowedAlgorithms) == 0 {
		c.AllowedAlgorithms = []Algorithm{
			HS256, HS384, HS512,
			RS256, RS384, RS512,
			PS256, PS384, PS512,
			ES256, ES384, ES512,
			EdDSA,
		}
	}
	if c.KeyManager == nil {
		c.KeyManager = NewKeyManager()
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	return c
}
