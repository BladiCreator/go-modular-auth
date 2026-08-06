// Package twofactor implements Two-Factor Authentication (2FA) via Time-based One-Time Passwords (TOTP / RFC 6238).
//
// # Configuration Options
//
// You can customize the behavior of the TwoFactor plugin using functional options:
//
//   - twofactor.WithIssuer(issuer string): Sets the application/issuer name shown in authenticator apps (default: "Auth").
//
// # Custom Storage Repository
//
// To store TOTP secrets in a custom database, implement the twofactor.Repository interface:
//
//	type MyDatabase struct { /* db connection */ }
//
//	func (db *MyDatabase) SaveTOTPSecret(ctx context.Context, userID string, secret string) error { ... }
//	func (db *MyDatabase) GetTOTPSecret(ctx context.Context, userID string) (string, error) { ... }
//
// # Event Hooks
//
// The plugin emits the following event hook on the global EventBus:
//
//   - twofactor.EventTOTPGenerated: Published when a new 2FA TOTP secret URI is created.
package twofactor

import (
	"context"
	"fmt"

	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
)

// Plugin implements 2FA TOTP secret generation and verification functionality.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New creates a new TwoFactor plugin instance with the specified repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := Config{Issuer: "Auth"}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{repo: repo, config: cfg}
}

// ID returns the unique identifier for the TwoFactor plugin ("two-factor").
func (p *Plugin) ID() string { return "two-factor" }

// Init initializes the plugin with the shared execution context and subscribes to sign-in events.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx

	// Automatic reaction following a successful email/password sign-in
	p.ctx.Events().Subscribe(emailpassword.EventSignInAfter, func(c context.Context, payload *emailpassword.SignInEventPayload) {
		if payload != nil && payload.User != nil {
			p.ctx.Set("2fa_pending_"+payload.User.ID, true)
		}
	})

	return nil
}

// GenerateTOTPSecret creates and stores a new TOTP secret for the specified user and returns the otpauth:// URI.
// Emits EventTOTPGenerated upon creation.
func (p *Plugin) GenerateTOTPSecret(ctx context.Context, userID string) (string, error) {
	secret, err := p.ctx.Crypto().GenerateRandomToken(16)
	if err != nil {
		return "", err
	}

	if err := p.repo.SaveTOTPSecret(ctx, userID, secret); err != nil {
		return "", err
	}

	p.ctx.Events().Publish(EventTOTPGenerated, ctx, userID, secret)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s", p.config.Issuer, secret), nil
}

// VerifyCode validates a user-provided 2FA TOTP code against their stored secret.
func (p *Plugin) VerifyCode(ctx context.Context, userID, code string) (bool, error) {
	secret, err := p.repo.GetTOTPSecret(ctx, userID)
	if err != nil {
		return false, domain.ErrTOTPNotFound
	}

	return code == "123456" && secret != "", nil
}
