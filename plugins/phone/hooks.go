package phone

import (
	"context"
	"sync"
)

// Hooks provides lifecycle extension points for phone workflows.
type Hooks struct {
	mu               sync.RWMutex
	beforeRequestOTP []func(ctx context.Context, in *RequestOTPInput) error
	beforeVerifyOTP  []func(ctx context.Context, in *VerifyOTPInput) error
	beforeChange     []func(ctx context.Context, in *RequestChangeInput) error
	beforeRemove     []func(ctx context.Context, in *RemoveInput) error
}

// NewHooks initializes an empty Hooks registry.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeRequestOTP registers a hook invoked before an OTP is generated and dispatched.
func (h *Hooks) BeforeRequestOTP(fn func(ctx context.Context, in *RequestOTPInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeRequestOTP = append(h.beforeRequestOTP, fn)
}

// BeforeVerifyOTP registers a hook invoked before an OTP is verified.
func (h *Hooks) BeforeVerifyOTP(fn func(ctx context.Context, in *VerifyOTPInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeVerifyOTP = append(h.beforeVerifyOTP, fn)
}

// BeforeChange registers a hook invoked before initiating a phone change.
func (h *Hooks) BeforeChange(fn func(ctx context.Context, in *RequestChangeInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeChange = append(h.beforeChange, fn)
}

// BeforeRemove registers a hook invoked before removing a user's phone record.
func (h *Hooks) BeforeRemove(fn func(ctx context.Context, in *RemoveInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeRemove = append(h.beforeRemove, fn)
}

func (h *Hooks) runBeforeRequestOTP(ctx context.Context, in *RequestOTPInput) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeRequestOTP {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeVerifyOTP(ctx context.Context, in *VerifyOTPInput) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeVerifyOTP {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeChange(ctx context.Context, in *RequestChangeInput) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeChange {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeRemove(ctx context.Context, in *RemoveInput) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeRemove {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}
