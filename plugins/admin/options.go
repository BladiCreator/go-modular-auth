package admin

import "time"

// Config contains runtime configuration parameters for the Admin plugin.
type Config struct {
	// DefaultRole is the default role assigned to users if none is specified (default: "user").
	DefaultRole string

	// AdminRoles is a list of roles considered to hold administrator privileges (default: ["admin"]).
	AdminRoles []string

	// AdminUserIDs is an explicit list of user IDs granted full administrative bypass access.
	AdminUserIDs []string

	// DefaultBanReason is the standard reason applied when suspending an account without a reason (default: "No reason provided").
	DefaultBanReason string

	// DefaultBanExpiresIn defines the default expiration duration for suspensions (default: 0, meaning permanent).
	DefaultBanExpiresIn time.Duration

	// ImpersonationSessionDuration defines the validity period for temporary impersonated sessions (default: 1 hour).
	ImpersonationSessionDuration time.Duration

	// BannedUserMessage is the user-facing message returned when a banned user attempts authentication.
	BannedUserMessage string

	// AllowImpersonatingAdmins specifies whether administrators can impersonate other administrators without explicit statement permission (default: false).
	AllowImpersonatingAdmins bool

	// MinPasswordLength is the minimum password length enforced by SetUserPassword (default: 8).
	MinPasswordLength int

	// MaxPasswordLength is the maximum allowed password length for SetUserPassword (default: 128).
	MaxPasswordLength int

	// Roles defines the complete dictionary of custom and built-in roles and statement permissions.
	Roles map[string]Role
}

// DefaultConfig returns the recommended baseline configuration for the Admin plugin.
func DefaultConfig() Config {
	return Config{
		DefaultRole:                  RoleUser,
		AdminRoles:                   []string{RoleAdmin},
		AdminUserIDs:                 nil,
		DefaultBanReason:             "No reason provided",
		DefaultBanExpiresIn:          0, // 0 = permanent
		ImpersonationSessionDuration: 1 * time.Hour,
		BannedUserMessage:            "You have been banned from this application. Please contact support if you believe this is an error.",
		AllowImpersonatingAdmins:     false,
		MinPasswordLength:            8,
		MaxPasswordLength:            128,
		Roles:                        DefaultRoles(),
	}
}

// Option defines a functional configuration mutator for the Admin plugin.
type Option func(*Config)

// WithDefaultRole sets the default role for users when unassigned.
func WithDefaultRole(role string) Option {
	return func(c *Config) {
		if role != "" {
			c.DefaultRole = role
		}
	}
}

// WithAdminRoles configures the role names recognized as administrators.
func WithAdminRoles(roles ...string) Option {
	return func(c *Config) {
		if len(roles) > 0 {
			c.AdminRoles = roles
		}
	}
}

// WithAdminUserIDs configures specific user IDs that automatically bypass permission checks.
func WithAdminUserIDs(userIDs ...string) Option {
	return func(c *Config) {
		c.AdminUserIDs = userIDs
	}
}

// WithDefaultBanReason sets the fallback reason string when suspending users.
func WithDefaultBanReason(reason string) Option {
	return func(c *Config) {
		if reason != "" {
			c.DefaultBanReason = reason
		}
	}
}

// WithDefaultBanExpiresIn sets the default expiration duration for account suspensions.
func WithDefaultBanExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		c.DefaultBanExpiresIn = d
	}
}

// WithImpersonationSessionDuration configures the expiration duration of temporary masquerade sessions.
func WithImpersonationSessionDuration(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ImpersonationSessionDuration = d
		}
	}
}

// WithBannedUserMessage sets the rejection message displayed to banned users.
func WithBannedUserMessage(msg string) Option {
	return func(c *Config) {
		if msg != "" {
			c.BannedUserMessage = msg
		}
	}
}

// WithAllowImpersonatingAdmins configures whether admins can masquerade as other admins.
func WithAllowImpersonatingAdmins(allow bool) Option {
	return func(c *Config) {
		c.AllowImpersonatingAdmins = allow
	}
}

// WithPasswordLength configures minimum and maximum password length limits for administrative password setting.
func WithPasswordLength(minLen, maxLen int) Option {
	return func(c *Config) {
		if minLen > 0 {
			c.MinPasswordLength = minLen
		}
		if maxLen >= minLen {
			c.MaxPasswordLength = maxLen
		}
	}
}

// WithCustomRoles replaces or configures the entire roles map.
func WithCustomRoles(roles map[string]Role) Option {
	return func(c *Config) {
		if roles != nil {
			c.Roles = make(map[string]Role, len(roles))
			for k, v := range roles {
				c.Roles[k] = Role{
					Name:       v.Name,
					Statements: CloneStatements(v.Statements),
				}
			}
		}
	}
}

// WithRole registers or overrides an individual role in the plugin configuration.
func WithRole(role Role) Option {
	return func(c *Config) {
		if c.Roles == nil {
			c.Roles = make(map[string]Role)
		}
		c.Roles[role.Name] = Role{
			Name:       role.Name,
			Statements: CloneStatements(role.Statements),
		}
	}
}
