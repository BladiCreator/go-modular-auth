package jwt

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// PayloadFunc defines a custom callback function to build additional custom claims for session-based JWTs.
type PayloadFunc func(session *entity.Session, user *entity.User) (map[string]any, error)

// SubjectFunc defines a custom callback function to resolve the "sub" (subject) claim for a session/user.
type SubjectFunc func(session *entity.Session, user *entity.User) (string, error)

// Config holds all configuration parameters for the JWT plugin.
type Config struct {
	// Issuer defines the "iss" claim value included in generated tokens (default: "GoModularAuth").
	Issuer string

	// Audience defines the "aud" claim list validated and included in generated tokens.
	Audience []string

	// ExpirationTime defines the validity duration ("exp" claim) for issued tokens (default: 15 minutes).
	ExpirationTime time.Duration

	// Algorithm specifies the asymmetric signature algorithm to use (default: AlgEdDSA / Ed25519).
	Algorithm Algorithm

	// RSABits specifies the key size in bits when using RSA algorithms (RS256/PS256, default: 2048).
	RSABits int

	// RotationInterval defines how frequently active signing keys should be rotated (0 = rotation disabled).
	RotationInterval time.Duration

	// GracePeriod defines how long expired keys remain available in JWKS for token verification (default: 30 days).
	GracePeriod time.Duration

	// Secret defines the symmetric encryption key used to protect private keys in storage via AES-256-GCM.
	Secret string

	// DisablePrivateKeyEncryption specifies whether private keys should be stored unencrypted in repository.
	DisablePrivateKeyEncryption bool

	// ClockSkewLeeway defines the acceptable clock skew window during exp and nbf validation (default: 1 minute).
	ClockSkewLeeway time.Duration

	// DefinePayload is an optional custom callback to inject extra claims into session-based tokens.
	DefinePayload PayloadFunc

	// GetSubject is an optional custom callback to resolve the "sub" claim from session and user.
	GetSubject SubjectFunc
}

// Option defines a functional configuration option for the JWT plugin.
type Option func(*Config)

// DefaultConfig returns the default production configuration for the JWT plugin.
func DefaultConfig() Config {
	return Config{
		Issuer:                      "GoModularAuth",
		Audience:                    nil,
		ExpirationTime:              15 * time.Minute,
		Algorithm:                   AlgEdDSA,
		RSABits:                     2048,
		RotationInterval:            0,
		GracePeriod:                 30 * 24 * time.Hour,
		Secret:                      "",
		DisablePrivateKeyEncryption: false,
		ClockSkewLeeway:             1 * time.Minute,
		DefinePayload:               nil,
		GetSubject:                  nil,
	}
}

// WithIssuer sets the issuer identifier ("iss" claim) included in issued JWT tokens.
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		if issuer != "" {
			c.Issuer = issuer
		}
	}
}

// WithAudience sets the recipient audience values ("aud" claim) for issued JWT tokens.
func WithAudience(audience ...string) Option {
	return func(c *Config) {
		c.Audience = audience
	}
}

// WithExpiration sets the default validity duration for issued JWT tokens.
func WithExpiration(duration time.Duration) Option {
	return func(c *Config) {
		if duration > 0 {
			c.ExpirationTime = duration
		}
	}
}

// WithAlgorithm sets the asymmetric cryptographic algorithm used for signing tokens.
func WithAlgorithm(alg Algorithm) Option {
	return func(c *Config) {
		c.Algorithm = alg
	}
}

// WithRSABits sets the RSA key size in bits (minimum 2048).
func WithRSABits(bits int) Option {
	return func(c *Config) {
		if bits >= 2048 {
			c.RSABits = bits
		}
	}
}

// WithRotationInterval configures automatic key rotation interval.
func WithRotationInterval(interval time.Duration) Option {
	return func(c *Config) {
		c.RotationInterval = interval
	}
}

// WithGracePeriod configures how long rotated/expired keys are preserved in JWKS for validation.
func WithGracePeriod(grace time.Duration) Option {
	return func(c *Config) {
		if grace >= 0 {
			c.GracePeriod = grace
		}
	}
}

// WithSecret sets the symmetric secret key used for AES-256-GCM private key encryption in repository.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithDisablePrivateKeyEncryption disables AES-256-GCM encryption of private keys in storage.
func WithDisablePrivateKeyEncryption(disable bool) Option {
	return func(c *Config) {
		c.DisablePrivateKeyEncryption = disable
	}
}

// WithClockSkewLeeway sets the time window tolerance allowed when validating exp and nbf claims.
func WithClockSkewLeeway(leeway time.Duration) Option {
	return func(c *Config) {
		if leeway >= 0 {
			c.ClockSkewLeeway = leeway
		}
	}
}

// WithDefinePayload configures a custom callback to generate custom claims for session tokens.
func WithDefinePayload(fn PayloadFunc) Option {
	return func(c *Config) {
		c.DefinePayload = fn
	}
}

// WithGetSubject configures a custom callback to resolve the "sub" claim for session tokens.
func WithGetSubject(fn SubjectFunc) Option {
	return func(c *Config) {
		c.GetSubject = fn
	}
}
