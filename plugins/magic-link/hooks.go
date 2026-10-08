package magiclink

import (
	"context"
	"sync"
)

// BeforeRequestHook runs before processing a magic link request.
// It can mutate the input or abort the request by returning an error.
type BeforeRequestHook func(ctx context.Context, in *RequestInput) error

// BeforeConsumeHook runs before consuming a magic link token.
// It can abort the consumption by returning an error.
type BeforeConsumeHook func(ctx context.Context, in *AuthenticateInput) error

// Hooks manages security hooks for magic link workflows.
type Hooks struct {
	mu            sync.RWMutex
	beforeRequest []BeforeRequestHook
	beforeConsume []BeforeConsumeHook
}

// NewHooks returns an empty hooks manager.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeRequest registers a hook invoked before processing a magic link request.
func (h *Hooks) BeforeRequest(fn BeforeRequestHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeRequest = append(h.beforeRequest, fn)
}

// BeforeConsume registers a hook invoked before consuming a magic link token.
func (h *Hooks) BeforeConsume(fn BeforeConsumeHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeConsume = append(h.beforeConsume, fn)
}

func (h *Hooks) runBeforeRequest(ctx context.Context, in *RequestInput) error {
	h.mu.RLock()
	fns := append([]BeforeRequestHook(nil), h.beforeRequest...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeConsume(ctx context.Context, in *AuthenticateInput) error {
	h.mu.RLock()
	fns := append([]BeforeConsumeHook(nil), h.beforeConsume...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}
