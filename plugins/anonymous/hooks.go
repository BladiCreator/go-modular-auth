package anonymous

import (
	"context"
	"sync"
)

// Hooks provides lifecycle interceptors for anonymous authentication workflows.
// Before hooks can inspect, mutate input, or abort the workflow by returning an error.
// After hooks observe the results after transactions commit.
type Hooks struct {
	beforeCreate  chain[AuthenticateInput]
	afterCreate   observers[AuthResult]
	beforeConvert chain[ConvertInput]
	afterConvert  observers[ConvertResult]
	beforeLink    chain[LinkInput]
	afterLink     observers[LinkResult]
	beforeCleanup chain[CleanupInput]
	afterCleanup  observers[CleanupResult]
}

// CleanupInput passes the threshold time to before cleanup hooks.
type CleanupInput struct {
	BeforeThreshold string
}

// NewHooks creates an initialized Hooks registry.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeCreate registers a hook called before anonymous identity creation.
func (h *Hooks) BeforeCreate(fn func(ctx context.Context, in *AuthenticateInput) error) {
	h.beforeCreate.add(fn)
}

// AfterCreate registers a hook called after anonymous identity and session creation.
func (h *Hooks) AfterCreate(fn func(ctx context.Context, res *AuthResult)) {
	h.afterCreate.add(fn)
}

// BeforeConvert registers a hook called before converting an anonymous user in-place.
func (h *Hooks) BeforeConvert(fn func(ctx context.Context, in *ConvertInput) error) {
	h.beforeConvert.add(fn)
}

// AfterConvert registers a hook called after conversion succeeds.
func (h *Hooks) AfterConvert(fn func(ctx context.Context, res *ConvertResult)) {
	h.afterConvert.add(fn)
}

// BeforeLink registers a hook called before merging an anonymous identity into a permanent account.
func (h *Hooks) BeforeLink(fn func(ctx context.Context, in *LinkInput) error) {
	h.beforeLink.add(fn)
}

// AfterLink registers a hook called after account linking succeeds.
func (h *Hooks) AfterLink(fn func(ctx context.Context, res *LinkResult)) {
	h.afterLink.add(fn)
}

// BeforeCleanup registers a hook called before cleanup runs.
func (h *Hooks) BeforeCleanup(fn func(ctx context.Context, in *CleanupInput) error) {
	h.beforeCleanup.add(fn)
}

// AfterCleanup registers a hook called after cleanup completes.
func (h *Hooks) AfterCleanup(fn func(ctx context.Context, res *CleanupResult)) {
	h.afterCleanup.add(fn)
}

func (h *Hooks) runBeforeCreate(ctx context.Context, in *AuthenticateInput) error {
	if h == nil {
		return nil
	}
	return h.beforeCreate.run(ctx, in)
}

func (h *Hooks) runAfterCreate(ctx context.Context, res *AuthResult) {
	if h == nil {
		return
	}
	h.afterCreate.run(ctx, res)
}

func (h *Hooks) runBeforeConvert(ctx context.Context, in *ConvertInput) error {
	if h == nil {
		return nil
	}
	return h.beforeConvert.run(ctx, in)
}

func (h *Hooks) runAfterConvert(ctx context.Context, res *ConvertResult) {
	if h == nil {
		return
	}
	h.afterConvert.run(ctx, res)
}

func (h *Hooks) runBeforeLink(ctx context.Context, in *LinkInput) error {
	if h == nil {
		return nil
	}
	return h.beforeLink.run(ctx, in)
}

func (h *Hooks) runAfterLink(ctx context.Context, res *LinkResult) {
	if h == nil {
		return
	}
	h.afterLink.run(ctx, res)
}

func (h *Hooks) runBeforeCleanup(ctx context.Context, in *CleanupInput) error {
	if h == nil {
		return nil
	}
	return h.beforeCleanup.run(ctx, in)
}

func (h *Hooks) runAfterCleanup(ctx context.Context, res *CleanupResult) {
	if h == nil {
		return
	}
	h.afterCleanup.run(ctx, res)
}

type chain[T any] struct {
	mu  sync.RWMutex
	fns []func(context.Context, *T) error
}

func (c *chain[T]) add(fn func(context.Context, *T) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fns = append(c.fns, fn)
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
	defer o.mu.Unlock()
	o.fns = append(o.fns, fn)
}

func (o *observers[T]) run(ctx context.Context, v *T) {
	o.mu.RLock()
	fns := o.fns
	o.mu.RUnlock()
	for _, fn := range fns {
		fn(ctx, v)
	}
}
