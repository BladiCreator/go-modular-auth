package jwt

import (
	"context"
	"sync"
)

// Hooks provides lifecycle extension points for JWT operations.
// Registered hooks execute synchronously and may mutate inputs or abort operations by returning an error.
type Hooks struct {
	mu           sync.RWMutex
	beforeIssue  []func(ctx context.Context, claims *Claims) error
	afterIssue   []func(ctx context.Context, tokenString string, claims *Claims) error
	beforeVerify []func(ctx context.Context, tokenString string) error
	afterVerify  []func(ctx context.Context, claims *Claims) error
	beforeRevoke []func(ctx context.Context, jti string) error
	afterRevoke  []func(ctx context.Context, jti string) error
}

// NewHooks initializes an empty Hooks registry.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeIssue registers an interceptor invoked before signing a token.
func (h *Hooks) BeforeIssue(fn func(ctx context.Context, claims *Claims) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeIssue = append(h.beforeIssue, fn)
}

// AfterIssue registers an interceptor invoked after a token is signed.
func (h *Hooks) AfterIssue(fn func(ctx context.Context, tokenString string, claims *Claims) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterIssue = append(h.afterIssue, fn)
}

// BeforeVerify registers an interceptor invoked before parsing and verifying a token.
func (h *Hooks) BeforeVerify(fn func(ctx context.Context, tokenString string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeVerify = append(h.beforeVerify, fn)
}

// AfterVerify registers an interceptor invoked after a token is verified and validated.
func (h *Hooks) AfterVerify(fn func(ctx context.Context, claims *Claims) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterVerify = append(h.afterVerify, fn)
}

// BeforeRevoke registers an interceptor invoked before revoking a token.
func (h *Hooks) BeforeRevoke(fn func(ctx context.Context, jti string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeRevoke = append(h.beforeRevoke, fn)
}

// AfterRevoke registers an interceptor invoked after a token is revoked.
func (h *Hooks) AfterRevoke(fn func(ctx context.Context, jti string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterRevoke = append(h.afterRevoke, fn)
}

func (h *Hooks) runBeforeIssue(ctx context.Context, claims *Claims) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeIssue {
		if err := fn(ctx, claims); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterIssue(ctx context.Context, tokenString string, claims *Claims) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterIssue {
		if err := fn(ctx, tokenString, claims); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeVerify(ctx context.Context, tokenString string) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeVerify {
		if err := fn(ctx, tokenString); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterVerify(ctx context.Context, claims *Claims) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterVerify {
		if err := fn(ctx, claims); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeRevoke(ctx context.Context, jti string) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeRevoke {
		if err := fn(ctx, jti); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterRevoke(ctx context.Context, jti string) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterRevoke {
		if err := fn(ctx, jti); err != nil {
			return err
		}
	}
	return nil
}
