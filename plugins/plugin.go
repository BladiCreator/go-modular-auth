// Package plugins provides convenient factory constructors for instantiating officially supported authentication plugins,
// such as EmailPassword and TwoFactor (TOTP).
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

// EmailPassword instantiates a new EmailPassword authentication plugin configured with the given repository and options.
//
// The EmailPassword plugin handles traditional user registration (sign-up), login authentication (sign-in),
// password changes, forgot/reset password flows, and lifecycle event hooks.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - emailpassword.WithMinPasswordLength(minLen int): Minimum password length required during registration (default: 8).
//   - emailpassword.WithRequireEmailVerification(require bool): Require email verification before sign-in (default: false).
//   - emailpassword.WithResetTokenExpiry(duration time.Duration): Expiry duration for reset tokens (default: 15 minutes).
//
// Example:
//
//	epPlugin := plugins.EmailPassword(
//		myRepository,
//		emailpassword.WithMinPasswordLength(10),
//		emailpassword.WithResetTokenExpiry(30 * time.Minute),
//	)
func EmailPassword(repo emailpassword.Repository, opts ...emailpassword.Option) *emailpassword.Plugin {
	return emailpassword.New(repo, opts...)
}

// TwoFactor instantiates a new TwoFactor (TOTP) authentication plugin configured with the given repository and options.
//
// The TwoFactor plugin provides Time-based One-Time Password (TOTP / RFC 6238) multi-factor authentication,
// generating secure secrets, creating otpauth:// URIs for authenticator apps (Google Authenticator, Authy, etc.),
// and verifying 6-digit TOTP codes.
func TwoFactor(repo twofactor.Repository, opts ...twofactor.Option) *twofactor.Plugin {
	return twofactor.New(repo, opts...)
}