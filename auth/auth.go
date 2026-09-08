// Package auth provides the core engine for initializing, configuring, and managing modular authentication plugins.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"golang.org/x/crypto/bcrypt"
)

// Auth is the central authentication engine holding initialized plugins, session orchestrators, execution pipelines, and lifecycle hooks.
type Auth struct {
	ctx            *plugin.Context
	pipeline       *plugin.Pipeline
	hooks          *plugin.Hooks
	sessionManager *SessionManager
	plugins        map[reflect.Type]plugin.Plugin
}

type defaultCrypto struct{ bcryptCost int }

func (c *defaultCrypto) HashPassword(p string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(p), c.bcryptCost)
	return string(b), err
}
func (c *defaultCrypto) ComparePassword(h, p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(p)) == nil
}
func (c *defaultCrypto) GenerateRandomToken(l int) (string, error) {
	b := make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// New creates and initializes a new Auth instance with the provided configuration options.
// It initializes all registered plugins with a shared plugin context and configures the central SessionManager if a repository is provided.
func New(opts ...config.Option) (*Auth, error) {
	cfg := config.DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	pipeline := plugin.NewPipeline()
	if len(cfg.Interceptors) > 0 {
		pipeline.AddInterceptor(cfg.Interceptors...)
	}

	hooks := cfg.Hooks
	if hooks == nil {
		hooks = plugin.NewHooks(cfg.AsyncHooks)
	} else if cfg.AsyncHooks {
		hooks.SetAsync(true)
	}

	crypto := &defaultCrypto{bcryptCost: cfg.BcryptCost}

	a := &Auth{
		pipeline: pipeline,
		hooks:    hooks,
		plugins:  make(map[reflect.Type]plugin.Plugin),
	}

	a.ctx = plugin.NewContext(crypto, plugin.WithPipeline(pipeline), plugin.WithHooks(hooks))

	if cfg.SessionRepository != nil {
		a.sessionManager = NewSessionManager(cfg.SessionRepository, cfg.SessionConfig, crypto, pipeline, hooks)
		a.ctx.SetSessionManager(a.sessionManager)
	}

	for _, p := range cfg.Plugins {
		if err := p.Init(a.ctx); err != nil {
			return nil, fmt.Errorf("Auth: failed to initialize plugin '%s': %w", p.ID(), err)
		}
		a.plugins[reflect.TypeOf(p)] = p
	}

	return a, nil
}

// Pipeline returns the synchronous execution pipeline for intercepting and mutating authentication operations.
func (a *Auth) Pipeline() *plugin.Pipeline {
	return a.pipeline
}

// Hooks returns the typed lifecycle hooks and native event dispatcher.
func (a *Auth) Hooks() *plugin.Hooks {
	return a.hooks
}

// SessionManager returns the central SessionManager orchestrator, or nil if no SessionRepository was configured.
func (a *Auth) SessionManager() *SessionManager {
	return a.sessionManager
}

// CreateSession creates and persists a new authenticated user session directly through the central SessionManager.
func (a *Auth) CreateSession(ctx context.Context, userID string, opts ...SessionOption) (*entity.Session, error) {
	if a.sessionManager == nil {
		return nil, ErrSessionRepositoryRequired
	}
	return a.sessionManager.CreateSession(ctx, userID, opts...)
}

// ValidateSession validates an active session token, returning combined user and session data directly through the central SessionManager.
func (a *Auth) ValidateSession(ctx context.Context, token string) (*dto.SessionData, error) {
	if a.sessionManager == nil {
		return nil, ErrSessionRepositoryRequired
	}
	return a.sessionManager.ValidateSession(ctx, token)
}

// RevokeSession revokes an active session by token directly through the central SessionManager.
func (a *Auth) RevokeSession(ctx context.Context, token string) error {
	if a.sessionManager == nil {
		return ErrSessionRepositoryRequired
	}
	return a.sessionManager.RevokeSession(ctx, token)
}

// VerifyChallenge completes an active MFA challenge (TOTP, backup code, OTP), atomically revoking the challenge token,
// and issues an authenticated session via the central SessionManager.
func (a *Auth) VerifyChallenge(ctx context.Context, params dto.VerifyChallengeParams, opts ...SessionOption) (*dto.SessionData, error) {
	if a.ctx == nil || a.ctx.MFAProvider() == nil {
		return nil, ErrMFAEngineNotConfigured
	}
	if a.sessionManager == nil {
		return nil, ErrSessionRepositoryRequired
	}

	verRes, err := a.ctx.MFAProvider().VerifyMFAChallenge(ctx, params)
	if err != nil {
		return nil, err
	}

	user, err := a.sessionManager.ResolveUser(ctx, verRes.UserID)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, fmt.Errorf("auth: failed to resolve user for verified challenge: %w", err)
	}

	sess, err := a.sessionManager.CreateSession(ctx, verRes.UserID, opts...)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to issue session: %w", err)
	}

	sessionData := &dto.SessionData{
		Session: sess,
		User:    user,
	}
	if sess.Extra != nil {
		sessionData.Extra = sess.Extra
	}

	if a.hooks != nil {
		a.hooks.DispatchUserSignedIn(ctx, sessionData)
	}

	return sessionData, nil
}

// VerifyTwoFactorChallenge is a convenient shortcut to verify a TOTP or backup code MFA challenge by token and code.
func (a *Auth) VerifyTwoFactorChallenge(ctx context.Context, challengeToken string, code string, opts ...SessionOption) (*dto.SessionData, error) {
	return a.VerifyChallenge(ctx, dto.VerifyChallengeParams{
		ChallengeToken: challengeToken,
		Code:           code,
		Method:         "totp",
	}, opts...)
}

// Plugin retrieves a registered plugin instance of type P from the Auth engine in a strongly-typed manner.
// It panics if the specified plugin has not been registered during engine initialization.
func Plugin[P any](a *Auth) *P {
	var zero P
	ptrType := reflect.TypeFor[*P]()
	if raw, ok := a.plugins[ptrType]; ok {
		if p, ok := any(raw).(*P); ok {
			return p
		}
	}

	structType := reflect.TypeFor[P]()
	if raw, ok := a.plugins[structType]; ok {
		if p, ok := any(raw).(*P); ok {
			return p
		}
	}

	panic(fmt.Sprintf("Auth: plugin %T is not registered", zero))
}
