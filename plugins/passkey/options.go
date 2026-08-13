package passkey

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/go-webauthn/webauthn/protocol"
)

// PasskeyRegistrationUser represents a resolved user identity when registering without an active session.
type PasskeyRegistrationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// Callback and hook function types.
type (
	// ResolveUserFunc is invoked to resolve or provision a user identity during registration when requireSession is false.
	ResolveUserFunc func(ctx context.Context, queryContext *string, extra map[string]any) (*PasskeyRegistrationUser, error)

	// AfterRegistrationHook is executed after a new passkey credential has been successfully verified and saved.
	AfterRegistrationHook func(ctx context.Context, passkey *entity.Passkey, user *entity.User) error

	// AfterAuthenticationHook is executed after a passkey assertion is verified and a new session created.
	AfterAuthenticationHook func(ctx context.Context, passkey *entity.Passkey, user *entity.User, session *entity.Session) error
)

// Config holds runtime configuration options for the Passkey plugin.
type Config struct {
	RPDisplayName                string                               // Relying Party human-readable name (default: "GoModularAuth")
	RPID                         string                               // Relying Party domain identifier (default: "localhost")
	RPOrigins                    []string                             // Allowed origin URLs (e.g. "http://localhost:3000")
	ChallengeTimeout             time.Duration                        // Ephemeral challenge lifespan (default: 5 minutes)
	RequireSessionOnRegistration bool                                 // Enforce caller session during registration (default: true)
	UserVerification             protocol.UserVerificationRequirement // User verification requirement (default: "preferred")
	ResidentKey                  protocol.ResidentKeyRequirement      // Resident key / Discoverable credential preference (default: "preferred")
	Attestation                  protocol.ConveyancePreference        // Attestation conveyance preference (default: "none")
	AuthenticatorAttachment      *protocol.AuthenticatorAttachment    // Optional attachment ("platform" or "cross-platform")
	SessionDuration              time.Duration                        // Lifespan of created user sessions (default: 7 days)
	ResolveUser                  ResolveUserFunc                      // User resolution callback
	AfterRegistration            AfterRegistrationHook                // Post-registration hook
	AfterAuthentication          AfterAuthenticationHook              // Post-authentication hook
}

// DefaultConfig returns a Config populated with production-ready defaults.
func DefaultConfig() Config {
	return Config{
		RPDisplayName:                "GoModularAuth",
		RPID:                         "localhost",
		RPOrigins:                    []string{"http://localhost:3000", "http://localhost:8080"},
		ChallengeTimeout:             5 * time.Minute,
		RequireSessionOnRegistration: true,
		UserVerification:             protocol.VerificationPreferred,
		ResidentKey:                  protocol.ResidentKeyRequirementPreferred,
		Attestation:                  protocol.PreferNoAttestation,
		AuthenticatorAttachment:      nil,
		SessionDuration:              7 * 24 * time.Hour,
		ResolveUser:                  nil,
		AfterRegistration:            nil,
		AfterAuthentication:          nil,
	}
}

// Option configures the Passkey plugin.
type Option func(*Config)

// WithRPDisplayName sets the Relying Party human-readable name.
func WithRPDisplayName(name string) Option {
	return func(c *Config) {
		if name != "" {
			c.RPDisplayName = name
		}
	}
}

// WithRPID sets the Relying Party domain identifier (e.g. "auth.example.com" or "localhost").
func WithRPID(rpID string) Option {
	return func(c *Config) {
		if rpID != "" {
			c.RPID = rpID
		}
	}
}

// WithRPOrigins sets the list of allowed origin URLs.
func WithRPOrigins(origins ...string) Option {
	return func(c *Config) {
		if len(origins) > 0 {
			c.RPOrigins = origins
		}
	}
}

// WithChallengeTimeout sets the validity duration for ephemeral challenges.
func WithChallengeTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ChallengeTimeout = d
		}
	}
}

// WithRequireSessionOnRegistration toggles whether registration requires an active authenticated caller.
func WithRequireSessionOnRegistration(require bool) Option {
	return func(c *Config) {
		c.RequireSessionOnRegistration = require
	}
}

// WithUserVerification sets the WebAuthn user verification preference.
func WithUserVerification(uv protocol.UserVerificationRequirement) Option {
	return func(c *Config) {
		c.UserVerification = uv
	}
}

// WithResidentKey sets the resident key (discoverable credential) preference.
func WithResidentKey(rk protocol.ResidentKeyRequirement) Option {
	return func(c *Config) {
		c.ResidentKey = rk
	}
}

// WithAttestation sets the attestation conveyance preference.
func WithAttestation(att protocol.ConveyancePreference) Option {
	return func(c *Config) {
		c.Attestation = att
	}
}

// WithAuthenticatorAttachment restricts authenticators to platform or cross-platform devices.
func WithAuthenticatorAttachment(attachment protocol.AuthenticatorAttachment) Option {
	return func(c *Config) {
		c.AuthenticatorAttachment = &attachment
	}
}

// WithSessionDuration sets the validity duration for sessions issued upon successful authentication.
func WithSessionDuration(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.SessionDuration = d
		}
	}
}

// WithResolveUser sets the callback to resolve user identity during unauthenticated registration flows.
func WithResolveUser(fn ResolveUserFunc) Option {
	return func(c *Config) {
		c.ResolveUser = fn
	}
}

// WithAfterRegistration sets the post-registration lifecycle hook.
func WithAfterRegistration(hook AfterRegistrationHook) Option {
	return func(c *Config) {
		c.AfterRegistration = hook
	}
}

// WithAfterAuthentication sets the post-authentication lifecycle hook.
func WithAfterAuthentication(hook AfterAuthenticationHook) Option {
	return func(c *Config) {
		c.AfterAuthentication = hook
	}
}
