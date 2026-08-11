// Package plugins provides convenient factory constructors for instantiating officially supported authentication plugins,
// such as EmailPassword (credential-based sign-in/sign-up) and TwoFactor (RFC 6238 TOTP, backup codes, challenge OTP).
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
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

// TwoFactor instantiates a new TwoFactor authentication plugin configured with the given repository and options.
//
// The TwoFactor plugin provides Time-based One-Time Password (TOTP / RFC 6238) multi-factor authentication,
// generating secure Base32 secrets, creating otpauth:// URIs for authenticator apps (Google Authenticator, Authy, 1Password),
// verifying 6- or 8-digit TOTP codes, managing single-use backup recovery codes, and dispatching SMS/Email OTP challenges.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - twofactor.WithIssuer(issuer string): Issuer name shown in authenticator apps (default: "GoModularAuth").
//   - twofactor.WithTOTPOptions(digits int, period int): Number of digits and duration period (default: 6 digits, 30s).
//   - twofactor.WithBackupCodeOptions(amount, length int): Number and length of backup codes (default: 10 codes, 10 chars).
//   - twofactor.WithLockoutProtection(maxAttempts int, duration time.Duration): Rate-limiting brute-force protection.
//   - twofactor.WithSendOTP(fn twofactor.SendOTPFunc): Delivery callback for SMS/Email OTP challenges.
//
// Example:
//
//	tfPlugin := plugins.TwoFactor(
//		myRepository,
//		twofactor.WithIssuer("My Application"),
//		twofactor.WithTOTPOptions(6, 30),
//		twofactor.WithBackupCodeOptions(10, 10),
//	)
func TwoFactor(repo twofactor.Repository, opts ...twofactor.Option) *twofactor.Plugin {
	return twofactor.New(repo, opts...)
}

// Bearer instantiates a new Bearer authentication plugin configured with an optional session repository and functional options.
//
// The Bearer plugin handles RFC 7235 compliant Bearer token extraction, HMAC-SHA256 cryptographic signing and verification
// with constant-time comparison, CORS header exposition, and seamless session resolution for API and mobile clients.
//
// # Configuration Options
//
// You can pass functional options to customize the plugin:
//
//   - bearer.WithSecret(secret string): Cryptographic HMAC secret key used for signing and verifying tokens.
//   - bearer.WithRequireSignature(require bool): Enforce that incoming tokens must already have a valid HMAC signature.
//   - bearer.WithTokenHeader(header string): Customize incoming authorization header name (default: "Authorization").
//   - bearer.WithAuthTokenHeader(header string): Customize outgoing token header name (default: "set-auth-token").
//   - bearer.WithExposeHeaders(expose bool): Enable CORS Access-Control-Expose-Headers propagation.
//
// Example:
//
//	bearerPlugin := plugins.Bearer(
//		myRepository,
//		bearer.WithSecret("my-cryptographic-secret-key"),
//		bearer.WithRequireSignature(false),
//	)
func Bearer(repo bearer.Repository, opts ...bearer.Option) *bearer.Plugin {
	return bearer.New(repo, opts...)
}
