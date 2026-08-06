// Package auth provides the core engine for initializing, configuring, and managing modular authentication plugins.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/asaskevich/EventBus"
	"golang.org/x/crypto/bcrypt"
)

// Auth is the central authentication engine holding initialized plugins and event dispatchers.
type Auth struct {
	ctx     *plugin.Context
	bus     EventBus.Bus
	plugins map[reflect.Type]plugin.Plugin
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
// It initializes all registered plugins with a shared plugin context.
func New(opts ...config.Option) (*Auth, error) {
	cfg := config.DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	bus := EventBus.New()
	crypto := &defaultCrypto{bcryptCost: cfg.BcryptCost}

	a := &Auth{
		bus:     bus,
		plugins: make(map[reflect.Type]plugin.Plugin),
	}

	a.ctx = plugin.NewContext(crypto, bus)

	for _, p := range cfg.Plugins {
		if err := p.Init(a.ctx); err != nil {
			return nil, fmt.Errorf("Auth: failed to initialize plugin '%s': %w", p.ID(), err)
		}
		a.plugins[reflect.TypeOf(p)] = p
	}

	return a, nil
}

// Events returns the global EventBus instance for subscribing to or publishing authentication lifecycle events.
func (a *Auth) Events() EventBus.Bus {
	return a.bus
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
