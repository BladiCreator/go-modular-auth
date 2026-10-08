package passkey

import (
	"net/url"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth-passkeys/challenge"
	"github.com/BladiCreator/go-modular-auth-passkeys/store"
	"github.com/BladiCreator/go-modular-auth-passkeys/store/memory"
	"github.com/go-webauthn/webauthn/protocol"
)

// DefaultTimeout is the default duration for WebAuthn ceremony expiration.
const DefaultTimeout = 60 * time.Second

// Config holds the configuration settings for the Passkey plugin.
type Config struct {
	// RPDisplayName is the human-readable Relying Party name (e.g. "Acme Corp"). Required.
	RPDisplayName string

	// RPID is the Relying Party server identifier (e.g. "acme.com" or "localhost"). Required.
	RPID string

	// RPOrigins lists the allowed origin URLs (e.g. "https://acme.com", "http://localhost:3000"). Required.
	RPOrigins []string

	// UserVerification specifies the default user verification requirement (required, preferred, discouraged).
	// Default: preferred.
	UserVerification protocol.UserVerificationRequirement

	// ResidentKey specifies the default resident key / discoverable credential requirement.
	// Default: preferred.
	ResidentKey protocol.ResidentKeyRequirement

	// Timeout defines the maximum duration allowed to complete a registration or login ceremony.
	// Default: 60 seconds.
	Timeout time.Duration

	// EnforceSignCounter ensures that authenticator sign counter regressions trigger clone detection errors.
	// Default: true.
	EnforceSignCounter bool

	// Store is the authoritative storage adapter for passkeys.
	// Defaults to in-memory store if nil.
	Store store.Store

	// ChallengeStore is the storage adapter for transient ceremony challenges.
	// Defaults to in-memory challenge store if nil.
	ChallengeStore challenge.Store

	// Hooks provides extension hooks for ceremony workflows.
	Hooks *Hooks

	// Debug enables verbose debug logging in the WebAuthn engine.
	Debug bool
}

func (c Config) withDefaults() (Config, error) {
	if strings.TrimSpace(c.RPDisplayName) == "" {
		return c, ErrRPDisplayNameRequired
	}

	trimmedRPID := strings.TrimSpace(c.RPID)
	if trimmedRPID == "" {
		return c, ErrRPIDRequired
	}
	if strings.Contains(trimmedRPID, "://") || strings.Contains(trimmedRPID, "/") || strings.Contains(trimmedRPID, ":") {
		return c, ErrInvalidRPID
	}
	c.RPID = trimmedRPID

	if len(c.RPOrigins) == 0 {
		return c, ErrRPOriginsRequired
	}
	for _, orig := range c.RPOrigins {
		u, err := url.Parse(orig)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return c, ErrInvalidRPOrigin
		}
	}

	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}

	if c.UserVerification == "" {
		c.UserVerification = protocol.VerificationPreferred
	}

	if c.ResidentKey == "" {
		c.ResidentKey = protocol.ResidentKeyRequirementPreferred
	}

	if c.Store == nil {
		c.Store = memory.New()
	}

	if c.ChallengeStore == nil {
		c.ChallengeStore = challenge.NewMemoryStore()
	}

	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}

	return c, nil
}

// Option applies a configuration option.
type Option func(*Config)

// WithRP sets the Relying Party identification and allowed origins.
func WithRP(id, displayName string, origins []string) Option {
	return func(c *Config) {
		c.RPID = id
		c.RPDisplayName = displayName
		c.RPOrigins = origins
	}
}

// WithUserVerification configures the user verification policy.
func WithUserVerification(uv protocol.UserVerificationRequirement) Option {
	return func(c *Config) {
		c.UserVerification = uv
	}
}

// WithResidentKey configures the resident key / discoverable credential policy.
func WithResidentKey(rk protocol.ResidentKeyRequirement) Option {
	return func(c *Config) {
		c.ResidentKey = rk
	}
}

// WithTimeout sets the ceremony timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		c.Timeout = d
	}
}

// WithEnforceSignCounter toggles sign counter validation and clone rejection.
func WithEnforceSignCounter(enforce bool) Option {
	return func(c *Config) {
		c.EnforceSignCounter = enforce
	}
}

// WithStore sets the authoritative passkey store adapter.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		c.Store = s
	}
}

// WithChallengeStore sets the transient ceremony challenge store.
func WithChallengeStore(cs challenge.Store) Option {
	return func(c *Config) {
		c.ChallengeStore = cs
	}
}

// WithHooks sets workflow lifecycle hooks.
func WithHooks(h *Hooks) Option {
	return func(c *Config) {
		c.Hooks = h
	}
}

// WithDebug enables or disables WebAuthn debug output.
func WithDebug(debug bool) Option {
	return func(c *Config) {
		c.Debug = debug
	}
}
