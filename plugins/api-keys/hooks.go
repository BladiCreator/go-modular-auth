package apikeys

import (
	"context"
	"sync"
)

// Hooks provides lifecycle interception points for the API keys module workflows.
type Hooks struct {
	beforeCreate       chain[CreateInput]
	afterCreate        observers[APIKey]
	beforeAuthenticate chain[string]
	afterAuthenticate  observers[AuthResult]
	beforeRevoke       chain[string]
	afterRevoke        observers[APIKey]
	beforeRotate       chain[string]
	afterRotate        observers[RotateResult]
}

// BeforeCreate runs before an API key is validated and persisted.
func (h *Hooks) BeforeCreate(fn func(ctx context.Context, in *CreateInput) error) {
	h.beforeCreate.add(fn)
}

// AfterCreate runs after an API key is persisted and published.
func (h *Hooks) AfterCreate(fn func(ctx context.Context, key *APIKey)) {
	h.afterCreate.add(fn)
}

// BeforeAuthenticate runs before validating candidate credentials.
func (h *Hooks) BeforeAuthenticate(fn func(ctx context.Context, rawKey *string) error) {
	h.beforeAuthenticate.add(fn)
}

// AfterAuthenticate runs after credentials are successfully verified and telemetry updated.
func (h *Hooks) AfterAuthenticate(fn func(ctx context.Context, res *AuthResult)) {
	h.afterAuthenticate.add(fn)
}

// BeforeRevoke runs before an API key revocation is applied in the store.
func (h *Hooks) BeforeRevoke(fn func(ctx context.Context, keyID *string) error) {
	h.beforeRevoke.add(fn)
}

// AfterRevoke runs after an API key is revoked and cache invalidated.
func (h *Hooks) AfterRevoke(fn func(ctx context.Context, key *APIKey)) {
	h.afterRevoke.add(fn)
}

// BeforeRotate runs before initiating rotation on an existing key.
func (h *Hooks) BeforeRotate(fn func(ctx context.Context, keyID *string) error) {
	h.beforeRotate.add(fn)
}

// AfterRotate runs after rotation finishes, returning both old and new keys.
func (h *Hooks) AfterRotate(fn func(ctx context.Context, res *RotateResult)) {
	h.afterRotate.add(fn)
}

type chain[T any] struct {
	mu  sync.RWMutex
	fns []func(context.Context, *T) error
}

func (c *chain[T]) add(fn func(context.Context, *T) error) {
	c.mu.Lock()
	c.fns = append(c.fns, fn)
	c.mu.Unlock()
}

func (c *chain[T]) run(ctx context.Context, v *T) error {
	c.mu.RLock()
	fns := c.fns
	c.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, v); err != nil {
			return err
		}
	}
	return nil
}

type observers[T any] struct {
	mu  sync.RWMutex
	fns []func(context.Context, *T)
}

func (o *observers[T]) add(fn func(context.Context, *T)) {
	o.mu.Lock()
	o.fns = append(o.fns, fn)
	o.mu.Unlock()
}

func (o *observers[T]) run(ctx context.Context, v *T) {
	o.mu.RLock()
	fns := o.fns
	o.mu.RUnlock()
	for _, fn := range fns {
		fn(ctx, v)
	}
}
