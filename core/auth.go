// Package auth is the core of GoModularAuth: a small, server-only,
// transport-agnostic authentication engine.
//
// The core defines what it means to authenticate (users, accounts,
// credentials, opaque sessions, verification tokens). Persistence is
// delegated to a Store adapter (source of truth), acceleration to an optional
// Cache adapter, delivery to an optional Email adapter, and optional
// capabilities to plugin modules. The core never imports net/http: transport
// adapters translate requests into calls such as SignIn or RequireSession.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/email"
	"github.com/BladiCreator/go-modular-auth/password"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/store"
)

// Auth is the authentication engine. It is safe for concurrent use and holds
// no global state: create as many independent instances as needed.
type Auth struct {
	cfg          Config
	store        store.Store
	cache        cache.Cache // nil when not configured
	sessionCache cache.SessionCache
	userCache    cache.UserCache
	email        email.Sender
	hasher       password.Hasher
	hooks        *Hooks
	events       *Events
	registry     *plugin.Registry
	logger       *slog.Logger
	dummyHash    func() string
}

// New builds an Auth instance and initializes its plugin modules.
func New(cfg Config) (*Auth, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	a := &Auth{
		cfg:      cfg,
		store:    cfg.Store,
		cache:    cfg.Cache,
		email:    cfg.Email,
		hasher:   cfg.Hasher,
		hooks:    &Hooks{},
		events:   newEvents(cfg.Logger),
		registry: plugin.NewRegistry(),
		logger:   cfg.Logger,
	}
	if cfg.Cache != nil {
		a.sessionCache = cache.NewSessionCache(cfg.Cache)
		a.userCache = cache.NewUserCache(cfg.Cache)
	}
	// Hash used to equalize SignIn timing when the user does not exist.
	a.dummyHash = sync.OnceValue(func() string {
		h, _ := a.hasher.Hash(context.Background(), "gomodularauth-timing-equalizer")
		return h
	})
	if err := a.initPlugins(cfg.Plugins); err != nil {
		return nil, err
	}
	return a, nil
}

// Get returns the plugin capability T registered by an installed module:
//
//	orgs, err := auth.Get[plugins.Organization](a)
func Get[T any](a *Auth) (T, error) {
	if a == nil || a.registry == nil {
		var zero T
		return zero, plugin.ErrNotFound
	}
	return plugin.Lookup[T](a.registry)
}

// MustGet is like Get but panics when the capability is missing. Use it only
// during application wiring.
func MustGet[T any](a *Auth) T {
	v, err := Get[T](a)
	if err != nil {
		panic(err)
	}
	return v
}

// Registry returns the capability registry.
func (a *Auth) Registry() *plugin.Registry { return a.registry }

// Hooks returns the workflow hooks registry.
func (a *Auth) Hooks() *Hooks { return a.hooks }

// Events returns the event dispatcher.
func (a *Auth) Events() *Events { return a.events }

// Store returns the configured store adapter.
func (a *Auth) Store() store.Store { return a.store }

// Cache returns the configured cache adapter, or nil.
func (a *Auth) Cache() cache.Cache { return a.cache }

// Email returns the configured email sender, or nil.
func (a *Auth) Email() email.Sender { return a.email }

// Logger returns the configured logger.
func (a *Auth) Logger() *slog.Logger { return a.logger }

// Now returns the current time according to the configured clock.
func (a *Auth) Now() time.Time { return a.cfg.Now() }

// PurgeExpired deletes expired sessions and verification tokens from the
// Store. Schedule it periodically (e.g. from a background job).
func (a *Auth) PurgeExpired(ctx context.Context) (sessions, tokens int, err error) {
	now := a.Now()
	sessions, err1 := a.store.Sessions().DeleteExpired(ctx, now)
	tokens, err2 := a.store.Tokens().DeleteExpired(ctx, now)
	return sessions, tokens, errors.Join(err1, err2)
}

func (a *Auth) publish(ctx context.Context, name EventName, subject string, payload any) {
	a.events.Publish(ctx, Event{Name: name, Time: a.Now(), Subject: subject, Payload: payload})
}
