package emailotp

import "context"

// RequestHook is invoked synchronously before processing an OTP request.
type RequestHook func(ctx context.Context, in *RequestInput) error

// VerifyHook is invoked synchronously before verifying an OTP code.
type VerifyHook func(ctx context.Context, in *VerifyInput) error

// Hooks manages synchronous interception hooks for the Email OTP workflow.
type Hooks struct {
	beforeRequest []RequestHook
	beforeVerify  []VerifyHook
}

// NewHooks initializes an empty Hooks collection.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeRequest registers a hook invoked before processing an OTP dispatch request.
func (h *Hooks) BeforeRequest(fn RequestHook) {
	if fn != nil {
		h.beforeRequest = append(h.beforeRequest, fn)
	}
}

// BeforeVerify registers a hook invoked before processing an OTP verification request.
func (h *Hooks) BeforeVerify(fn VerifyHook) {
	if fn != nil {
		h.beforeVerify = append(h.beforeVerify, fn)
	}
}

func (h *Hooks) runBeforeRequest(ctx context.Context, in *RequestInput) error {
	if h == nil {
		return nil
	}
	for _, fn := range h.beforeRequest {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeVerify(ctx context.Context, in *VerifyInput) error {
	if h == nil {
		return nil
	}
	for _, fn := range h.beforeVerify {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}
