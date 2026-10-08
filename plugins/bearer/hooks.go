package bearer

import (
	"context"
	"sync"
)

// Hooks provides lifecycle extension points for bearer token operations.
// Registered hooks execute synchronously and may mutate inputs or abort operations by returning an error.
type Hooks struct {
	mu                 sync.RWMutex
	beforeIssue        []func(ctx context.Context, in *IssueInput) error
	afterIssue         []func(ctx context.Context, res *IssueResult) error
	beforeAuthenticate []func(ctx context.Context, in *AuthenticateInput) error
	afterAuthenticate  []func(ctx context.Context, res *AuthResult) error
	beforeRevoke       []func(ctx context.Context, tokenID string) error
	afterRevoke        []func(ctx context.Context, tokenID string) error
}

// NewHooks initializes an empty Hooks registry.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeIssue registers an interceptor invoked before generating and saving a new bearer token.
func (h *Hooks) BeforeIssue(fn func(ctx context.Context, in *IssueInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeIssue = append(h.beforeIssue, fn)
}

// AfterIssue registers an interceptor invoked after a bearer token has been persisted.
func (h *Hooks) AfterIssue(fn func(ctx context.Context, res *IssueResult) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterIssue = append(h.afterIssue, fn)
}

// BeforeAuthenticate registers an interceptor invoked before authenticating a bearer token.
func (h *Hooks) BeforeAuthenticate(fn func(ctx context.Context, in *AuthenticateInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeAuthenticate = append(h.beforeAuthenticate, fn)
}

// AfterAuthenticate registers an interceptor invoked after successfully authenticating a bearer token.
func (h *Hooks) AfterAuthenticate(fn func(ctx context.Context, res *AuthResult) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterAuthenticate = append(h.afterAuthenticate, fn)
}

// BeforeRevoke registers an interceptor invoked before revoking a token.
func (h *Hooks) BeforeRevoke(fn func(ctx context.Context, tokenID string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeRevoke = append(h.beforeRevoke, fn)
}

// AfterRevoke registers an interceptor invoked after a token is marked revoked.
func (h *Hooks) AfterRevoke(fn func(ctx context.Context, tokenID string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterRevoke = append(h.afterRevoke, fn)
}

func (h *Hooks) runBeforeIssue(ctx context.Context, in *IssueInput) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeIssue {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterIssue(ctx context.Context, res *IssueResult) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterIssue {
		if err := fn(ctx, res); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeAuthenticate(ctx context.Context, in *AuthenticateInput) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeAuthenticate {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterAuthenticate(ctx context.Context, res *AuthResult) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterAuthenticate {
		if err := fn(ctx, res); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeRevoke(ctx context.Context, tokenID string) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeRevoke {
		if err := fn(ctx, tokenID); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterRevoke(ctx context.Context, tokenID string) error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterRevoke {
		if err := fn(ctx, tokenID); err != nil {
			return err
		}
	}
	return nil
}
